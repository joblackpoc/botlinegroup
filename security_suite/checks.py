from django.core.checks import Error, Warning, Info, register
from django.conf import settings
import os


def check_security_settings(app_configs, **kwargs):
    """
    Django system check for security settings.
    """
    errors = []
    
    # Check SECRET_KEY
    if hasattr(settings, 'SECRET_KEY'):
        if settings.SECRET_KEY == 'django-insecure-' or len(settings.SECRET_KEY) < 50:
            errors.append(
                Error(
                    'Insecure SECRET_KEY detected',
                    hint='Generate a strong SECRET_KEY for production',
                    id='security.E001',
                )
            )
    
    # Check DEBUG setting
    if hasattr(settings, 'DEBUG') and settings.DEBUG:
        errors.append(
            Warning(
                'DEBUG is True',
                hint='Set DEBUG=False in production',
                id='security.W001',
            )
        )
    
    # Check ALLOWED_HOSTS
    if hasattr(settings, 'ALLOWED_HOSTS'):
        if not settings.ALLOWED_HOSTS and not settings.DEBUG:
            errors.append(
                Error(
                    'ALLOWED_HOSTS is empty',
                    hint='Set ALLOWED_HOSTS in production',
                    id='security.E002',
                )
            )
        elif '*' in settings.ALLOWED_HOSTS:
            errors.append(
                Warning(
                    'ALLOWED_HOSTS contains wildcard',
                    hint='Avoid using "*" in ALLOWED_HOSTS',
                    id='security.W002',
                )
            )
    
    # Check SECURE_SSL_REDIRECT
    if not getattr(settings, 'SECURE_SSL_REDIRECT', False) and not settings.DEBUG:
        errors.append(
            Warning(
                'SECURE_SSL_REDIRECT is not enabled',
                hint='Enable SECURE_SSL_REDIRECT to force HTTPS',
                id='security.W003',
            )
        )
    
    # Check SESSION_COOKIE_SECURE
    if not getattr(settings, 'SESSION_COOKIE_SECURE', False) and not settings.DEBUG:
        errors.append(
            Warning(
                'SESSION_COOKIE_SECURE is not enabled',
                hint='Enable SESSION_COOKIE_SECURE for HTTPS sites',
                id='security.W004',
            )
        )
    
    # Check CSRF_COOKIE_SECURE
    if not getattr(settings, 'CSRF_COOKIE_SECURE', False) and not settings.DEBUG:
        errors.append(
            Warning(
                'CSRF_COOKIE_SECURE is not enabled',
                hint='Enable CSRF_COOKIE_SECURE for HTTPS sites',
                id='security.W005',
            )
        )
    
    # Check SECURE_BROWSER_XSS_FILTER
    if not getattr(settings, 'SECURE_BROWSER_XSS_FILTER', False):
        errors.append(
            Warning(
                'SECURE_BROWSER_XSS_FILTER is not enabled',
                hint='Enable SECURE_BROWSER_XSS_FILTER for XSS protection',
                id='security.W006',
            )
        )
    
    # Check SECURE_CONTENT_TYPE_NOSNIFF
    if not getattr(settings, 'SECURE_CONTENT_TYPE_NOSNIFF', False):
        errors.append(
            Warning(
                'SECURE_CONTENT_TYPE_NOSNIFF is not enabled',
                hint='Enable SECURE_CONTENT_TYPE_NOSNIFF to prevent MIME sniffing',
                id='security.W007',
            )
        )
    
    # Check X_FRAME_OPTIONS
    if not hasattr(settings, 'X_FRAME_OPTIONS'):
        errors.append(
            Warning(
                'X_FRAME_OPTIONS is not set',
                hint='Set X_FRAME_OPTIONS to "DENY" or "SAMEORIGIN"',
                id='security.W008',
            )
        )
    
    # Check for security middleware
    middleware = getattr(settings, 'MIDDLEWARE', [])
    
    security_middleware = [
        'django.middleware.security.SecurityMiddleware',
        'security_suite.middleware.SecurityMiddleware',
        'security_suite.middleware.SessionSecurityMiddleware',
    ]
    
    for mw in security_middleware:
        if mw not in middleware:
            errors.append(
                Warning(
                    f'{mw} not in MIDDLEWARE',
                    hint=f'Add {mw} to MIDDLEWARE for enhanced security',
                    id='security.W009',
                )
            )
    
    # Check password validators
    validators = getattr(settings, 'AUTH_PASSWORD_VALIDATORS', [])
    if len(validators) < 4:
        errors.append(
            Warning(
                'Insufficient password validators',
                hint='Add more password validators for stronger passwords',
                id='security.W010',
            )
        )
    
    # Check for custom user model
    if not hasattr(settings, 'AUTH_USER_MODEL'):
        errors.append(
            Info(
                'Using default User model',
                hint='Consider using a custom User model',
                id='security.I001',
            )
        )
    
    # Check session settings
    if getattr(settings, 'SESSION_COOKIE_AGE', 1209600) > 3600:  # Default is 2 weeks
        errors.append(
            Info(
                'Long session timeout',
                hint='Consider reducing SESSION_COOKIE_AGE for better security',
                id='security.I002',
            )
        )
    
    # Check for Redis cache (recommended for security features)
    caches = getattr(settings, 'CACHES', {})
    if 'default' in caches:
        backend = caches['default'].get('BACKEND', '')
        if 'redis' not in backend.lower():
            errors.append(
                Info(
                    'Not using Redis for caching',
                    hint='Consider using Redis for better performance and security features',
                    id='security.I003',
                )
            )
    
    # Check for email configuration
    if not getattr(settings, 'EMAIL_BACKEND', None):
        errors.append(
            Warning(
                'EMAIL_BACKEND not configured',
                hint='Configure email for security notifications',
                id='security.W011',
            )
        )
    
    # Check for logging configuration
    if not getattr(settings, 'LOGGING', None):
        errors.append(
            Warning(
                'LOGGING not configured',
                hint='Configure logging for security auditing',
                id='security.W012',
            )
        )
    
    # Check file upload settings
    max_size = getattr(settings, 'FILE_UPLOAD_MAX_MEMORY_SIZE', 2621440)
    if max_size > 10 * 1024 * 1024:  # 10MB
        errors.append(
            Info(
                'Large file upload size',
                hint='Consider reducing FILE_UPLOAD_MAX_MEMORY_SIZE',
                id='security.I004',
            )
        )
    
    # Check for security-related settings
    security_settings = {
        'SECURE_HSTS_SECONDS': 'Enable HSTS with SECURE_HSTS_SECONDS',
        'SECURE_HSTS_INCLUDE_SUBDOMAINS': 'Enable SECURE_HSTS_INCLUDE_SUBDOMAINS',
        'SECURE_PROXY_SSL_HEADER': 'Set SECURE_PROXY_SSL_HEADER if behind proxy',
    }
    
    for setting, hint in security_settings.items():
        if not getattr(settings, setting, None) and not settings.DEBUG:
            errors.append(
                Info(
                    f'{setting} not configured',
                    hint=hint,
                    id='security.I005',
                )
            )
    
    return errors


# Register the check
register(check_security_settings)