from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden, HttpResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from ipware import get_client_ip
from .models import IPBlacklist, SessionMonitor, SecurityConfiguration
from .utils import (
    is_ip_blacklisted, create_security_headers, 
    log_security_event, get_client_info
)
import logging
import re
import hashlib

logger = logging.getLogger(__name__)


class SecurityMiddleware(MiddlewareMixin):
    """
    Comprehensive security middleware for the application.
    """
    
    def process_request(self, request):
        """Process incoming requests for security checks"""
        
        # Get client IP
        client_ip, is_routable = get_client_ip(request)
        request.client_ip = client_ip
        request.is_routable_ip = is_routable
        
        # 1. Check if IP is blacklisted
        if is_ip_blacklisted(client_ip):
            logger.warning(f"Blacklisted IP attempted access: {client_ip}")
            return HttpResponseForbidden("Access denied")
        
        # 2. Check for too many requests from this IP (simple rate limiting)
        if self._check_rate_limit(request, client_ip):
            return HttpResponse("Too many requests", status=429)
        
        # 3. Session security checks
        if request.user.is_authenticated:
            self._check_session_security(request)
        
        # 4. Check for common attack patterns in request
        attack_response = self._check_attack_patterns(request)
        if attack_response:
            return attack_response
        
        # 5. Add security context to request
        request.security_context = {
            'ip': client_ip,
            'is_routable': is_routable,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'timestamp': timezone.now()
        }
        
        return None
    
    def process_response(self, request, response):
        """Add security headers to response"""
        
        # Add security headers
        security_headers = create_security_headers()
        for header, value in security_headers.items():
            response[header] = value
        
        # Add additional headers based on configuration
        config = SecurityConfiguration.get_active_config()
        
        if config.secure_cookie:
            # Ensure cookies are secure
            response.set_cookie = self._wrap_set_cookie_secure(response.set_cookie, request)
        
        # Log suspicious response codes
        if hasattr(request, 'user') and response.status_code in [401, 403, 404, 500]:
            if response.status_code == 404:
                # Only log suspicious 404s
                if self._is_suspicious_404(request):
                    log_security_event(
                        event_type='suspicious_activity',
                        severity='warning',
                        message=f'Suspicious 404: {request.path}',
                        request=request,
                        status_code=response.status_code
                    )
            else:
                log_security_event(
                    event_type='data_viewed',
                    severity='warning' if response.status_code < 500 else 'error',
                    message=f'Error response: {response.status_code}',
                    request=request,
                    status_code=response.status_code
                )
        
        return response
    
    def _check_rate_limit(self, request, client_ip):
        """Simple rate limiting check"""
        config = SecurityConfiguration.get_active_config()
        
        if not config.rate_limit_enabled:
            return False
        
        # Different limits for authenticated vs anonymous
        if request.user.is_authenticated:
            limit = config.rate_limit_requests * 2  # Double for authenticated
            key = f'rate_limit:user:{request.user.id}'
        else:
            limit = config.rate_limit_requests
            key = f'rate_limit:ip:{client_ip}'
        
        # Get current count
        current = cache.get(key, 0)
        
        if current >= limit:
            log_security_event(
                event_type='rate_limit',
                severity='warning',
                message=f'Rate limit exceeded: {current}/{limit}',
                request=request
            )
            return True
        
        # Increment with expiry
        cache.set(key, current + 1, config.rate_limit_period_seconds)
        
        return False
    
    def _check_session_security(self, request):
        """Check session security for authenticated users"""
        if not hasattr(request, 'session') or not request.session.session_key:
            return
        
        try:
            # Get or create session monitor
            session_monitor, created = SessionMonitor.objects.get_or_create(
                session_key_hash=hashlib.sha256(
                    request.session.session_key.encode()
                ).hexdigest(),
                defaults={
                    'user': request.user,
                    'ip_address': request.client_ip,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'expires_at': request.session.get_expiry_date(),
                }
            )
            
            if not created:
                # Update last activity
                session_monitor.update_activity('page_view')
                
                # Check for IP change
                if session_monitor.ip_address != request.client_ip:
                    session_monitor.add_anomaly_flag('ip_change')
                    
                    log_security_event(
                        event_type='suspicious_activity',
                        severity='warning',
                        message='Session IP address changed',
                        request=request,
                        old_ip=session_monitor.ip_address,
                        new_ip=request.client_ip
                    )
                
                # Check if session should be terminated
                if session_monitor.terminated or session_monitor.is_expired():
                    request.session.flush()
                    return redirect('login')
            
            # Store session monitor in request
            request.session_monitor = session_monitor
            
        except Exception as e:
            logger.error(f"Error in session security check: {e}")
    
    def _check_attack_patterns(self, request):
        """Check for common attack patterns in request"""
        
        # SQL Injection patterns
        sql_patterns = [
            r"(\b(union|select|insert|update|delete|drop|create)\b.*\b(from|where|table)\b)",
            r"(;|\||`|\\x00|\\x1a)",
            r"(\b(or|and)\b\s*\d+\s*=\s*\d+)",
        ]
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"<object",
            r"<embed",
        ]
        
        # Path traversal patterns
        path_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e",
            r"%252e%252e",
        ]
        
        # Check all input sources
        check_items = []
        
        # GET parameters
        if request.GET:
            check_items.extend(request.GET.values())
        
        # POST data (limit check size)
        if request.method == 'POST' and request.body:
            try:
                if len(request.body) < 10240:  # 10KB limit
                    check_items.append(request.body.decode('utf-8', errors='ignore'))
            except:
                pass
        
        # Headers
        suspicious_headers = ['Referer', 'User-Agent', 'X-Forwarded-For']
        for header in suspicious_headers:
            value = request.META.get(f'HTTP_{header.upper().replace("-", "_")}', '')
            if value:
                check_items.append(value)
        
        # Check patterns
        for item in check_items:
            item_lower = str(item).lower()
            
            # SQL Injection
            for pattern in sql_patterns:
                if re.search(pattern, item_lower, re.IGNORECASE):
                    log_security_event(
                        event_type='sql_injection',
                        severity='high',
                        message='Potential SQL injection attempt',
                        request=request,
                        pattern=pattern,
                        matched_input=item[:100]
                    )
                    return HttpResponseForbidden("Invalid request")
            
            # XSS
            for pattern in xss_patterns:
                if re.search(pattern, item_lower, re.IGNORECASE):
                    log_security_event(
                        event_type='xss_attempt',
                        severity='high',
                        message='Potential XSS attempt',
                        request=request,
                        pattern=pattern,
                        matched_input=item[:100]
                    )
                    return HttpResponseForbidden("Invalid request")
            
            # Path Traversal
            for pattern in path_patterns:
                if re.search(pattern, item, re.IGNORECASE):
                    log_security_event(
                        event_type='directory_traversal',
                        severity='high',
                        message='Potential path traversal attempt',
                        request=request,
                        pattern=pattern,
                        matched_input=item[:100]
                    )
                    return HttpResponseForbidden("Invalid request")
        
        return None
    
    def _is_suspicious_404(self, request):
        """Check if a 404 is suspicious (scanning attempt)"""
        suspicious_paths = [
            'admin', 'wp-', 'php', '.git', '.env', 'config',
            'backup', 'sql', 'db', 'phpmyadmin', 'mysql'
        ]
        
        path_lower = request.path.lower()
        return any(pattern in path_lower for pattern in suspicious_paths)
    
    def _wrap_set_cookie_secure(self, original_set_cookie, request):
        """Wrapper to ensure cookies are set securely"""
        def wrapped_set_cookie(key, value='', **kwargs):
            # Force secure settings
            config = SecurityConfiguration.get_active_config()
            
            if config.secure_cookie and request.is_secure():
                kwargs['secure'] = True
            
            if config.httponly_cookie:
                kwargs['httponly'] = True
            
            if config.samesite_cookie:
                kwargs['samesite'] = config.samesite_cookie
            
            return original_set_cookie(key, value, **kwargs)
        
        return wrapped_set_cookie


class SessionSecurityMiddleware(MiddlewareMixin):
    """
    Middleware specifically for session security.
    """
    
    def process_request(self, request):
        """Check session security on each request"""
        
        if not request.user.is_authenticated:
            return None
        
        # Check for session timeout
        if hasattr(request, 'session'):
            last_activity = request.session.get('last_activity')
            
            if last_activity:
                config = SecurityConfiguration.get_active_config()
                last_activity_time = timezone.datetime.fromisoformat(last_activity)
                
                if timezone.now() - last_activity_time > timezone.timedelta(
                    minutes=config.session_timeout_minutes
                ):
                    # Session timeout
                    log_security_event(
                        event_type='session_expired',
                        severity='info',
                        message='Session timed out due to inactivity',
                        request=request
                    )
                    
                    request.session.flush()
                    return redirect('login')
            
            # Update last activity
            request.session['last_activity'] = timezone.now().isoformat()
        
        return None


class AuditMiddleware(MiddlewareMixin):
    """
    Middleware for comprehensive audit logging.
    """
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        """Log view access"""
        
        # Skip logging for static files and certain paths
        skip_paths = ['/static/', '/media/', '/favicon.ico', '/__debug__/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Log API access for authenticated users
        if request.user.is_authenticated and request.path.startswith('/api/'):
            log_security_event(
                event_type='data_viewed',
                severity='info',
                message=f'API access: {request.path}',
                request=request,
                view_name=view_func.__name__,
                method=request.method
            )
        
        return None


class CSRFFailureMiddleware(MiddlewareMixin):
    """
    Middleware to handle CSRF failures with security logging.
    """
    
    def process_view(self, request, callback, callback_args, callback_kwargs):
        """Check for CSRF token on state-changing methods"""
        
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            # This is handled by Django's CSRF middleware
            # We just add logging in the failure case
            pass
        
        return None


def csrf_failure(request, reason=""):
    """
    Custom CSRF failure view with security logging.
    """
    log_security_event(
        event_type='csrf_attack',
        severity='high',
        message=f'CSRF validation failed: {reason}',
        request=request,
        csrf_reason=reason
    )
    
    # Return forbidden response
    from django.http import HttpResponseForbidden
    return HttpResponseForbidden(
        '<h1>403 Forbidden</h1><p>CSRF verification failed.</p>',
        content_type='text/html'
    )