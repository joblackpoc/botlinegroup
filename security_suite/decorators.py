# security_suite/decorators.py

from functools import wraps
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect
from django.contrib.auth.decorators import user_passes_test
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
from django.conf import settings
from .models import SecurityConfiguration, IPBlacklist
from .utils import get_client_info, is_ip_blacklisted, log_security_event
from ipware import get_client_ip
import logging

logger = logging.getLogger(__name__)


def require_security_clearance(view_func):
    """
    Decorator to ensure user has security clearance to access security features.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        # Check if user has security permissions
        has_clearance = (
            request.user.is_staff or
            request.user.has_perm('security_suite.view_securityalert') or
            hasattr(request.user, 'security_clearance') and request.user.security_clearance
        )
        
        if not has_clearance:
            log_security_event(
                event_type='unauthorized_access',
                severity='warning',
                message=f'Security clearance required for {request.path}',
                request=request
            )
            return HttpResponseForbidden(_('Security clearance required'))
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view


def check_ip_whitelist(view_func):
    """
    Decorator to check if IP is whitelisted when whitelist is enabled.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        client_ip, _ = get_client_ip(request)
        
        # Check if IP is blacklisted first
        if is_ip_blacklisted(client_ip):
            log_security_event(
                event_type='ip_blocked',
                severity='warning',
                message=f'Blacklisted IP attempted access: {client_ip}',
                request=request
            )
            return HttpResponseForbidden(_('Access denied'))
        
        # Check whitelist if enabled
        config = SecurityConfiguration.get_active_config()
        if config.ip_whitelist_enabled:
            if client_ip not in config.ip_whitelist:
                log_security_event(
                    event_type='unauthorized_access',
                    severity='warning',
                    message=f'Non-whitelisted IP attempted access: {client_ip}',
                    request=request
                )
                return HttpResponseForbidden(_('Access denied'))
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view


def rate_limit(key='ip', rate='10/m', method='ALL'):
    """
    Custom rate limiting decorator with security logging.
    
    Args:
        key: 'ip' or 'user' - what to rate limit by
        rate: Rate limit string (e.g., '10/m', '100/h')
        method: HTTP method(s) to limit - 'ALL' or specific method
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Check if method matches
            if method != 'ALL' and request.method != method:
                return view_func(request, *args, **kwargs)
            
            # Determine rate limit key
            if key == 'user' and request.user.is_authenticated:
                limit_key = f'rate_limit:user:{request.user.id}'
            else:
                client_ip, _ = get_client_ip(request)
                limit_key = f'rate_limit:ip:{client_ip}'
            
            # Parse rate limit
            try:
                limit, period = rate.split('/')
                limit = int(limit)
                
                period_seconds = {
                    's': 1,
                    'm': 60,
                    'h': 3600,
                    'd': 86400
                }.get(period, 60)
                
            except (ValueError, KeyError):
                logger.error(f"Invalid rate limit format: {rate}")
                return view_func(request, *args, **kwargs)
            
            # Check rate limit
            current_count = cache.get(limit_key, 0)
            
            if current_count >= limit:
                # Log rate limit violation
                log_security_event(
                    event_type='rate_limit',
                    severity='warning',
                    message=f'Rate limit exceeded: {rate}',
                    request=request,
                    rate_limit=rate,
                    current_count=current_count
                )
                
                # Auto-blacklist severe violations
                if current_count >= limit * 2:  # Double the limit
                    client_ip, _ = get_client_ip(request)
                    IPBlacklist.objects.get_or_create(
                        ip_address=client_ip,
                        defaults={
                            'reason': 'rate_limit',
                            'description': f'Auto-blocked: Exceeded rate limit {rate} with {current_count} requests',
                            'auto_blocked': True,
                            'threat_score': 60.0
                        }
                    )
                
                return JsonResponse(
                    {'error': _('Rate limit exceeded')},
                    status=429
                )
            
            # Increment counter
            cache.set(limit_key, current_count + 1, period_seconds)
            
            # Add rate limit headers
            response = view_func(request, *args, **kwargs)
            response['X-RateLimit-Limit'] = str(limit)
            response['X-RateLimit-Remaining'] = str(limit - current_count - 1)
            response['X-RateLimit-Reset'] = str(period_seconds)
            
            return response
        
        return wrapped_view
    return decorator


def require_mfa(view_func):
    """
    Decorator to require MFA for sensitive operations.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        # Check if user has MFA enabled
        if not getattr(request.user, 'mfa_enabled', False):
            # Check if MFA is required by config
            config = SecurityConfiguration.get_active_config()
            if config.mfa_required:
                log_security_event(
                    event_type='mfa_bypass',
                    severity='warning',
                    message='User attempted sensitive operation without MFA',
                    request=request
                )
                return redirect('enable_mfa')
        
        # Check if MFA was verified recently
        mfa_verified_at = request.session.get('mfa_verified_at')
        if not mfa_verified_at:
            return redirect('verify_mfa')
        
        # Check if MFA verification has expired (30 minutes)
        from datetime import datetime, timedelta
        verified_time = datetime.fromisoformat(mfa_verified_at)
        if datetime.now() - verified_time > timedelta(minutes=30):
            request.session.pop('mfa_verified_at', None)
            return redirect('verify_mfa')
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view


def log_activity(action, severity='info'):
    """
    Decorator to automatically log activity for a view.
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Log the activity
            log_security_event(
                event_type=action,
                severity=severity,
                message=f'{action} accessed',
                request=request,
                view_name=view_func.__name__,
                args=str(args),
                kwargs=str(kwargs)
            )
            
            # Execute the view
            response = view_func(request, *args, **kwargs)
            
            # Log successful completion
            if hasattr(response, 'status_code') and response.status_code < 400:
                log_security_event(
                    event_type=action,
                    severity='info',
                    message=f'{action} completed successfully',
                    request=request,
                    status_code=response.status_code
                )
            
            return response
        
        return wrapped_view
    return decorator


def validate_request_signature(view_func):
    """
    Decorator to validate request signatures for API security.
    """
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Skip for GET requests
        if request.method == 'GET':
            return view_func(request, *args, **kwargs)
        
        # Get signature from headers
        signature = request.headers.get('X-Signature')
        if not signature:
            log_security_event(
                event_type='suspicious_activity',
                severity='warning',
                message='Missing request signature',
                request=request
            )
            return JsonResponse(
                {'error': _('Invalid request signature')},
                status=401
            )
        
        # Validate signature
        import hmac
        import hashlib
        
        # Get request body
        body = request.body or b''
        
        # Create expected signature
        secret = getattr(settings, 'API_SIGNATURE_SECRET', settings.SECRET_KEY)
        expected_signature = hmac.new(
            secret.encode(),
            body,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures
        if not hmac.compare_digest(signature, expected_signature):
            log_security_event(
                event_type='suspicious_activity',
                severity='high',
                message='Invalid request signature',
                request=request,
                provided_signature=signature[:10] + '...'  # Log partial signature
            )
            return JsonResponse(
                {'error': _('Invalid request signature')},
                status=401
            )
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view


def admin_required(view_func):
    """
    Decorator to require admin privileges.
    """
    return user_passes_test(
        lambda u: u.is_authenticated and u.is_staff,
        login_url='login'
    )(view_func)


def superuser_required(view_func):
    """
    Decorator to require superuser privileges.
    """
    return user_passes_test(
        lambda u: u.is_authenticated and u.is_superuser,
        login_url='login'
    )(view_func)