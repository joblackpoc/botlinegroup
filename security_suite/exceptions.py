from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import (
    ValidationError, PermissionDenied, NotFound,
    AuthenticationFailed, Throttled, APIException
)
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.http import Http404
from django.db import IntegrityError
from django.utils.translation import gettext_lazy as _
from audit_trail.models import AuditLog
from .models import SecurityAlert
from .utils import sanitize_path, log_security_event
from ipware import get_client_ip
import logging
import traceback
from django.utils import timezone
from django.conf import settings
import uuid

logger = logging.getLogger(__name__)


class SecurityException(APIException):
    """Base exception for security-related errors"""
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _('A security error occurred.')
    default_code = 'security_error'


class RateLimitExceeded(SecurityException):
    """Rate limit exceeded exception"""
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = _('Rate limit exceeded. Please try again later.')
    default_code = 'rate_limit_exceeded'


class IPBlacklistedException(SecurityException):
    """IP address is blacklisted"""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _('Access denied from this IP address.')
    default_code = 'ip_blacklisted'


class SessionExpiredException(SecurityException):
    """Session has expired"""
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Session has expired. Please login again.')
    default_code = 'session_expired'


class MFARequiredException(SecurityException):
    """MFA is required but not enabled"""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _('Multi-factor authentication is required.')
    default_code = 'mfa_required'


class SuspiciousActivityException(SecurityException):
    """Suspicious activity detected"""
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _('Suspicious activity detected. Access denied.')
    default_code = 'suspicious_activity'


def custom_exception_handler(exc, context):
    """Enhanced exception handler with comprehensive security logging"""
    
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    # Get request details
    request = context.get('request')
    view = context.get('view')
    
    # Extract client information
    client_ip = None
    user = None
    user_agent = ''
    
    if request:
        client_ip, _ = get_client_ip(request)
        user = getattr(request, 'user', None)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    # Determine severity based on exception type
    severity = 'error'
    create_alert = False
    
    # Handle specific exceptions
    if isinstance(exc, (PermissionDenied, DjangoPermissionDenied)):
        severity = 'warning'
        create_alert = True
        
        # Log unauthorized access attempt
        if request and user and user.is_authenticated:
            log_security_event(
                event_type='unauthorized_access',
                severity='warning',
                message=f'Unauthorized access attempt to {sanitize_path(request.path)}',
                request=request,
                user=user,
                view_name=view.__class__.__name__ if view else None,
                method=request.method if request else None,
            )
        
        # Create or enhance response
        if response is None:
            response = Response(
                {
                    'error': _('You do not have permission to perform this action.'),
                    'code': 'permission_denied'
                },
                status=status.HTTP_403_FORBIDDEN
            )
    
    elif isinstance(exc, Http404):
        severity = 'info'
        
        # Check for potential scanning
        if request and client_ip:
            path_lower = request.path.lower()
            suspicious_patterns = [
                'wp-admin', 'phpMyAdmin', '.php', 'admin.php',
                '.env', 'config', '.git', 'backup', '.sql',
                'phpmyadmin', 'pma', 'mysql', 'cpanel'
            ]
            
            if any(pattern in path_lower for pattern in suspicious_patterns):
                severity = 'warning'
                create_alert = True
                
                log_security_event(
                    event_type='suspicious_activity',
                    severity='warning',
                    message=f'Potential scanning attempt: {sanitize_path(request.path)}',
                    request=request,
                    scan_type='path_scanning',
                    suspicious_path=sanitize_path(request.path)
                )
        
        if response is None:
            response = Response(
                {
                    'error': _('Resource not found.'),
                    'code': 'not_found'
                },
                status=status.HTTP_404_NOT_FOUND
            )
    
    elif isinstance(exc, ValidationError):
        severity = 'info'
        
        # Log validation errors that might indicate attacks
        if request and hasattr(exc, 'detail'):
            error_detail = str(exc.detail)
            
            # Check for SQL injection attempts
            sql_patterns = ['union', 'select', 'drop', 'insert', 'update', 'delete', '--', '/*', '*/']
            if any(pattern in error_detail.lower() for pattern in sql_patterns):
                severity = 'high'
                create_alert = True
                
                log_security_event(
                    event_type='sql_injection',
                    severity='high',
                    message='Potential SQL injection attempt detected',
                    request=request,
                    attack_vector=error_detail[:200]  # Limit length
                )
        
        if response is None:
            response = Response(
                {
                    'error': _('Invalid input.'),
                    'errors': exc.detail if hasattr(exc, 'detail') else str(exc),
                    'code': 'validation_error'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
    
    elif isinstance(exc, AuthenticationFailed):
        severity = 'warning'
        
        # Log authentication failures
        if request:
            log_security_event(
                event_type='login_failed',
                severity='warning',
                message='Authentication failed',
                request=request,
                reason=str(exc)
            )
        
        if response is None:
            response = Response(
                {
                    'error': _('Authentication failed.'),
                    'code': 'authentication_failed'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    elif isinstance(exc, Throttled):
        severity = 'warning'
        create_alert = True
        
        # Log rate limit violations
        if request:
            log_security_event(
                event_type='rate_limit',
                severity='warning',
                message='Rate limit exceeded',
                request=request,
                wait_time=exc.wait if hasattr(exc, 'wait') else None
            )
        
        if response is None:
            wait_time = exc.wait if hasattr(exc, 'wait') else None
            response = Response(
                {
                    'error': _('Request was throttled.'),
                    'code': 'throttled',
                    'retry_after': wait_time
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
    
    elif isinstance(exc, IntegrityError):
        severity = 'error'
        
        # Log database integrity errors (might indicate attacks)
        logger.error(f"Database integrity error: {str(exc)}")
        
        if response is None:
            response = Response(
                {
                    'error': _('A database error occurred.'),
                    'code': 'integrity_error'
                },
                status=status.HTTP_409_CONFLICT
            )
    
    elif isinstance(exc, SecurityException):
        # Handle custom security exceptions
        severity = 'high'
        create_alert = True
        
        if request:
            log_security_event(
                event_type=exc.default_code,
                severity='high',
                message=str(exc),
                request=request
            )
        
        if response is None:
            response = Response(
                {
                    'error': str(exc.detail),
                    'code': exc.default_code
                },
                status=exc.status_code
            )
    
    else:
        # Handle unexpected exceptions
        severity = 'critical'
        create_alert = True
        
        # Log full traceback for debugging
        logger.error(
            f"Unhandled exception in {view.__class__.__name__ if view else 'unknown'}: "
            f"{type(exc).__name__}: {str(exc)}\n"
            f"Traceback: {traceback.format_exc()}"
        )
        
        # Log critical error to audit trail
        if response and response.status_code >= 500:
            if request:
                log_security_event(
                    event_type='data_viewed',  # Generic action for errors
                    severity='error',
                    message=f'Server error: {type(exc).__name__}',
                    request=request,
                    exception_type=type(exc).__name__,
                    exception_message=str(exc)[:500],  # Limit length
                    status_code=response.status_code,
                )
    
    # Create security alert for high-severity events
    if create_alert and severity in ['high', 'critical'] and request:
        try:
            SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity=severity,
                title=f'{type(exc).__name__} from {client_ip or "unknown"}',
                description=f'Exception: {str(exc)[:500]}',
                ip_address=client_ip,
                user=user if user and user.is_authenticated else None,
                user_agent=user_agent,
                details={
                    'exception_type': type(exc).__name__,
                    'view': view.__class__.__name__ if view else None,
                    'method': request.method if request else None,
                    'path': sanitize_path(request.path) if request else None,
                }
            )
        except Exception as e:
            logger.error(f"Failed to create security alert: {e}")
    
    # Ensure we always return a response
    if response is None:
        response = Response(
            {
                'error': _('An unexpected error occurred.'),
                'code': 'internal_error'
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    
    # Add security headers to all error responses
    response['X-Content-Type-Options'] = 'nosniff'
    response['X-Frame-Options'] = 'DENY'
    response['X-XSS-Protection'] = '1; mode=block'
    response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Add rate limit headers if applicable
    if isinstance(exc, Throttled) and hasattr(exc, 'wait'):
        response['Retry-After'] = str(exc.wait)
        response['X-RateLimit-Limit'] = '100'  # Configure based on your settings
        response['X-RateLimit-Remaining'] = '0'
    
    # Add CORS headers if needed
    if request and request.method == 'OPTIONS':
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    
    return response


# Error view handlers for Django (non-API) views

from django.shortcuts import render
from django.views.generic import TemplateView


def custom_400(request, exception=None):
    """Enhanced 400 Bad Request handler"""
    # Log the bad request
    client_ip, _ = get_client_ip(request)
    logger.warning(f"400 Bad Request from {client_ip}: {sanitize_path(request.path)}")
    
    # Check for potential attacks
    if request.method == 'POST' and request.body:
        # Check for oversized requests (potential DoS)
        if len(request.body) > 1024 * 1024:  # 1MB
            log_security_event(
                event_type='suspicious_activity',
                severity='warning',
                message='Oversized request detected',
                request=request,
                request_size=len(request.body)
            )
    
    context = {
        'error_code': 400,
        'error_title': _('Bad Request'),
        'error_message': _('The request could not be understood by the server.'),
        'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
    }
    return render(request, 'errors/error.html', context, status=400)


def custom_403(request, exception=None):
    """Enhanced 403 Forbidden handler with comprehensive logging"""
    # Log the forbidden access with sanitized path
    if hasattr(request, 'user') and request.user.is_authenticated:
        client_ip, _ = get_client_ip(request)
        
        # Detailed logging for authenticated users
        log_security_event(
            event_type='unauthorized_access',
            severity='warning',
            message=f'403 Forbidden: {sanitize_path(request.path)}',
            request=request,
            user=request.user,
            attempted_resource=sanitize_path(request.path),
            referer=request.META.get('HTTP_REFERER', ''),
            query_string=request.META.get('QUERY_STRING', '')
        )
        
        # Check for privilege escalation attempts
        if any(admin_path in request.path for admin_path in ['/admin/', '/api/admin/']):
            SecurityAlert.objects.create(
                alert_type='privilege_escalation',
                severity='high',
                title=f'Admin access attempt by {request.user.email}',
                description=f'Non-admin user tried to access admin area',
                user=request.user,
                ip_address=client_ip,
                details={
                    'path': sanitize_path(request.path),
                    'user_permissions': list(request.user.get_all_permissions())
                }
            )
    
    context = {
        'error_code': 403,
        'error_title': _('Access Forbidden'),
        'error_message': _('You do not have permission to access this resource.'),
        'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
    }
    return render(request, 'errors/error.html', context, status=403)


def custom_404(request, exception=None):
    """Enhanced 404 Not Found handler with security monitoring"""
    # Log 404s for monitoring (potential scanning)
    client_ip, _ = get_client_ip(request)
    path = sanitize_path(request.path)
    
    logger.info(f"404 Not Found from {client_ip}: {path}")
    
    # Enhanced scanning detection
    suspicious_patterns = [
        # Web shells and admin panels
        'wp-admin', 'wp-login', 'phpMyAdmin', 'pma', 'admin.php',
        'shell.php', 'c99.php', 'r57.php', 'wso.php',
        # Common vulnerabilities
        '.env', '.git', '.svn', '.DS_Store', 'web.config',
        'backup', '.sql', '.bak', '.old', '.zip', '.tar',
        # Framework specific
        'vendor/', 'node_modules/', 'webpack', '.map',
        # Database related
        'phpmyadmin', 'mysql', 'myadmin', 'sqladmin',
        # Common exploits
        'eval-stdin', 'invokefunction', 'struts', 'cgi-bin'
    ]
    
    path_lower = request.path.lower()
    is_suspicious = any(pattern in path_lower for pattern in suspicious_patterns)
    
    # Enhanced check for automated scanners
    user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
    scanner_patterns = ['scanner', 'nikto', 'nmap', 'sqlmap', 'burp', 'zap', 'acunetix']
    is_scanner = any(pattern in user_agent for pattern in scanner_patterns)
    
    if is_suspicious or is_scanner:
        # Log as potential security threat
        log_security_event(
            event_type='suspicious_activity',
            severity='warning',
            message=f'Potential {"scanner" if is_scanner else "scanning"} detected',
            request=request,
            scan_type='automated_scanner' if is_scanner else 'path_enumeration',
            suspicious_path=path,
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Create alert for repeated scanning from same IP
        from django.core.cache import cache
        scan_key = f'scan_attempts:{client_ip}'
        scan_count = cache.get(scan_key, 0) + 1
        cache.set(scan_key, scan_count, 3600)  # Track for 1 hour
        
        if scan_count >= 10:  # Threshold for alerting
            SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='high',
                title=f'Aggressive scanning from {client_ip}',
                description=f'Multiple scanning attempts detected ({scan_count} in last hour)',
                ip_address=client_ip,
                details={
                    'scan_count': scan_count,
                    'latest_path': path,
                    'user_agent': user_agent
                }
            )
    
    context = {
        'error_code': 404,
        'error_title': _('Page Not Found'),
        'error_message': _('The page you are looking for could not be found.'),
        'home_url': '/',
    }
    return render(request, 'errors/error.html', context, status=404)


def custom_500(request):
    """Enhanced 500 Internal Server Error handler"""
    # Log critical error
    client_ip, _ = get_client_ip(request)
    path = sanitize_path(request.path)
    
    logger.error(f"500 Internal Server Error: {path} from {client_ip}")
    
    # Create high-priority security alert for 500 errors
    try:
        SecurityAlert.objects.create(
            alert_type='suspicious_activity',
            severity='high',
            title='500 Internal Server Error',
            description=f'Server error occurred at {path}',
            ip_address=client_ip,
            user=request.user if hasattr(request, 'user') and request.user.is_authenticated else None,
            details={
                'path': path,
                'method': request.method,
                'timestamp': timezone.now().isoformat(),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'referer': request.META.get('HTTP_REFERER', '')
            },
            risk_score=75.0  # High risk score for server errors
        )
    except Exception as e:
        logger.error(f"Failed to create alert for 500 error: {e}")
    
    # Send notification to admins for critical errors
    try:
        from django.core.mail import mail_admins
        from django.conf import settings
        
        if getattr(settings, 'SEND_500_EMAILS', True):
            subject = f'500 Error at {path}'
            message = f"""
            500 Internal Server Error occurred:
            
            Path: {path}
            IP: {client_ip}
            Time: {timezone.now()}
            User: {request.user if hasattr(request, 'user') else 'Anonymous'}
            Method: {request.method}
            User-Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')}
            """
            
            mail_admins(subject, message, fail_silently=True)
    except Exception as e:
        logger.error(f"Failed to send 500 error email: {e}")
    
    context = {
        'error_code': 500,
        'error_title': _('Internal Server Error'),
        'error_message': _('An unexpected error occurred. Our team has been notified and is working to resolve the issue.'),
        'support_email': getattr(settings, 'SUPPORT_EMAIL', 'support@example.com'),
        'request_id': str(uuid.uuid4()),  # For tracking
    }
    return render(request, 'errors/error.html', context, status=500)


def custom_503(request, exception=None):
    """503 Service Unavailable handler"""
    context = {
        'error_code': 503,
        'error_title': _('Service Unavailable'),
        'error_message': _('The service is temporarily unavailable. Please try again later.'),
        'retry_after': 300,  # 5 minutes
    }
    response = render(request, 'errors/error.html', context, status=503)
    response['Retry-After'] = '300'
    return response