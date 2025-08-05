# security_suite/utils.py

import re
import hashlib
import secrets
from datetime import timedelta
from django.utils import timezone
from django.utils.html import escape
from django.core.cache import cache
from django.conf import settings
from ipware import get_client_ip
import ipaddress
import logging

logger = logging.getLogger(__name__)


def sanitize_path(path):
    """
    Sanitize URL path for safe logging and display.
    Prevents log injection and XSS attacks.
    """
    if not path:
        return ''
    
    # Remove query parameters that might contain sensitive data
    path = path.split('?')[0]
    
    # Remove any null bytes
    path = path.replace('\x00', '')
    
    # Escape HTML entities
    path = escape(path)
    
    # Remove any control characters
    path = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', path)
    
    # Limit length to prevent log flooding
    max_length = 255
    if len(path) > max_length:
        path = path[:max_length] + '...'
    
    return path


def mask_email(email):
    """
    Mask email address for privacy in logs and displays.
    Example: john.doe@example.com -> jo***e@example.com
    """
    if not email or '@' not in email:
        return 'unknown@example.com'
    
    try:
        local, domain = email.split('@', 1)
        
        if len(local) <= 3:
            # Very short local part, mask all
            masked_local = '*' * len(local)
        else:
            # Show first 2 and last 1 character
            masked_local = local[:2] + '*' * (len(local) - 3) + local[-1]
        
        return f"{masked_local}@{domain}"
    except Exception:
        return 'invalid@example.com'


def mask_ip(ip_address):
    """
    Partially mask IP address for privacy.
    IPv4: 192.168.1.100 -> 192.168.1.xxx
    IPv6: 2001:db8::1 -> 2001:db8::xxxx
    """
    if not ip_address:
        return 'unknown'
    
    try:
        ip = ipaddress.ip_address(ip_address)
        
        if isinstance(ip, ipaddress.IPv4Address):
            # Mask last octet
            parts = str(ip).split('.')
            return f"{'.'.join(parts[:3])}.xxx"
        else:
            # IPv6 - mask last segment
            parts = str(ip).split(':')
            if len(parts) > 1:
                parts[-1] = 'xxxx'
            return ':'.join(parts)
    except Exception:
        return 'invalid-ip'


def rate_limit_check(user_id, action, limit=10, window=60):
    """
    Check if a user has exceeded rate limit for a specific action.
    
    Args:
        user_id: User identifier
        action: Action being performed
        limit: Maximum number of allowed actions
        window: Time window in seconds
    
    Returns:
        tuple: (is_allowed, remaining_attempts)
    """
    cache_key = f"rate_limit:{action}:{user_id}"
    
    # Get current count
    current_count = cache.get(cache_key, 0)
    
    if current_count >= limit:
        return False, 0
    
    # Increment counter
    cache.set(cache_key, current_count + 1, window)
    
    return True, limit - current_count - 1


def generate_secure_token(length=32):
    """
    Generate a cryptographically secure random token.
    """
    return secrets.token_urlsafe(length)


def hash_sensitive_data(data, salt=None):
    """
    Hash sensitive data using SHA256 with optional salt.
    """
    if salt is None:
        salt = getattr(settings, 'SECRET_KEY', 'default-salt')
    
    hash_input = f"{salt}:{data}".encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()


def is_ip_whitelisted(ip_address):
    """
    Check if an IP address is in the whitelist.
    """
    from .models import SecurityConfiguration
    
    try:
        config = SecurityConfiguration.get_active_config()
        
        if not config.ip_whitelist_enabled:
            return True
        
        if not config.ip_whitelist:
            # Whitelist enabled but empty means block all
            return False
        
        ip = ipaddress.ip_address(ip_address)
        
        for whitelisted_ip in config.ip_whitelist:
            if str(ip) == whitelisted_ip:
                return True
        
        return False
    except Exception as e:
        logger.error(f"Error checking IP whitelist: {e}")
        # Fail open in case of error
        return True


def is_ip_blacklisted(ip_address):
    """
    Check if an IP address is blacklisted.
    """
    from .models import IPBlacklist
    
    try:
        # Check exact match
        blacklist_entry = IPBlacklist.objects.filter(
            ip_address=ip_address,
            is_active=True
        ).first()
        
        if blacklist_entry:
            # Check if expired
            if blacklist_entry.is_expired():
                blacklist_entry.is_active = False
                blacklist_entry.save()
                return False
            
            # Increment hit count
            blacklist_entry.increment_attempts()
            return True
        
        # Check CIDR ranges
        ip = ipaddress.ip_address(ip_address)
        cidr_entries = IPBlacklist.objects.filter(
            is_active=True,
            ip_range__isnull=False
        )
        
        for entry in cidr_entries:
            try:
                network = ipaddress.ip_network(entry.ip_range)
                if ip in network:
                    entry.increment_attempts()
                    return True
            except Exception:
                continue
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking IP blacklist: {e}")
        return False


def get_client_info(request):
    """
    Extract comprehensive client information from request.
    """
    client_ip, is_routable = get_client_ip(request)
    
    info = {
        'ip_address': client_ip or 'unknown',
        'is_routable': is_routable,
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        'referer': request.META.get('HTTP_REFERER', ''),
        'accept_language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        'method': request.method,
        'path': sanitize_path(request.path),
        'is_secure': request.is_secure(),
        'is_ajax': request.headers.get('X-Requested-With') == 'XMLHttpRequest',
    }
    
    # Extract device type from user agent
    user_agent_lower = info['user_agent'].lower()
    if 'mobile' in user_agent_lower or 'android' in user_agent_lower:
        info['device_type'] = 'mobile'
    elif 'tablet' in user_agent_lower or 'ipad' in user_agent_lower:
        info['device_type'] = 'tablet'
    else:
        info['device_type'] = 'desktop'
    
    return info


def check_password_strength(password):
    """
    Check password strength and return score and feedback.
    """
    from .models import SecurityConfiguration
    
    config = SecurityConfiguration.get_active_config()
    feedback = []
    score = 0
    
    # Length check
    if len(password) >= config.min_password_length:
        score += 25
    else:
        feedback.append(f"Password must be at least {config.min_password_length} characters long")
    
    # Uppercase check
    if config.require_uppercase:
        if any(c.isupper() for c in password):
            score += 25
        else:
            feedback.append("Password must contain at least one uppercase letter")
    
    # Lowercase check
    if config.require_lowercase:
        if any(c.islower() for c in password):
            score += 25
        else:
            feedback.append("Password must contain at least one lowercase letter")
    
    # Number check
    if config.require_numbers:
        if any(c.isdigit() for c in password):
            score += 25
        else:
            feedback.append("Password must contain at least one number")
    
    # Special character check
    if config.require_special_chars:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if any(c in special_chars for c in password):
            score += 25
        else:
            feedback.append("Password must contain at least one special character")
    
    # Additional checks for very strong passwords
    if len(password) >= 16:
        score = min(score + 10, 100)
    
    # Check for common patterns
    common_patterns = [
        r'12345', r'qwerty', r'password', r'admin', r'letmein',
        r'welcome', r'123456789', r'football', r'iloveyou'
    ]
    
    password_lower = password.lower()
    for pattern in common_patterns:
        if pattern in password_lower:
            score = max(score - 20, 0)
            feedback.append("Password contains common patterns")
            break
    
    return {
        'score': score,
        'strength': get_password_strength_label(score),
        'feedback': feedback,
        'valid': score >= 80 and len(feedback) == 0
    }


def get_password_strength_label(score):
    """
    Convert password score to human-readable label.
    """
    if score < 20:
        return 'very_weak'
    elif score < 40:
        return 'weak'
    elif score < 60:
        return 'fair'
    elif score < 80:
        return 'good'
    else:
        return 'strong'


def calculate_session_timeout():
    """
    Calculate session timeout based on current configuration.
    """
    from .models import SecurityConfiguration
    
    try:
        config = SecurityConfiguration.get_active_config()
        return timezone.now() + timedelta(minutes=config.session_timeout_minutes)
    except Exception:
        # Default to 30 minutes
        return timezone.now() + timedelta(minutes=30)


def should_force_mfa(user):
    """
    Check if MFA should be enforced for a user.
    """
    from .models import SecurityConfiguration
    
    if not user.is_authenticated:
        return False
    
    try:
        config = SecurityConfiguration.get_active_config()
        
        if not config.mfa_required:
            return False
        
        # Already has MFA enabled
        if hasattr(user, 'mfa_enabled') and user.mfa_enabled:
            return False
        
        # Superusers must always have MFA
        if user.is_superuser:
            return True
        
        # Check grace period
        if hasattr(user, 'date_joined'):
            grace_period_end = user.date_joined + timedelta(days=config.mfa_grace_period_days)
            if timezone.now() < grace_period_end:
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error checking MFA requirement: {e}")
        return False


def create_security_headers():
    """
    Create security headers dictionary based on configuration.
    """
    from .models import SecurityConfiguration
    
    headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    }
    
    try:
        config = SecurityConfiguration.get_active_config()
        
        if config.security_headers_enabled:
            if config.content_security_policy:
                headers['Content-Security-Policy'] = config.content_security_policy
            
            if config.strict_transport_security:
                headers['Strict-Transport-Security'] = config.strict_transport_security
        
    except Exception as e:
        logger.error(f"Error creating security headers: {e}")
    
    return headers


def log_security_event(event_type, severity, message, request=None, user=None, **kwargs):
    """
    Centralized security event logging.
    """
    from .models import SecurityAlert
    from audit_trail.models import AuditLog
    
    try:
        # Extract request info if available
        if request:
            client_ip, _ = get_client_ip(request)
            user = user or getattr(request, 'user', None)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        else:
            client_ip = kwargs.get('ip_address', '')
            user_agent = kwargs.get('user_agent', '')
        
        # Log to audit trail
        AuditLog.log(
            action=event_type,
            user=user if user and user.is_authenticated else None,
            severity=severity,
            message=message,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata=kwargs
        )
        
        # Create security alert for high severity events
        if severity in ['critical', 'high']:
            SecurityAlert.objects.create(
                alert_type=event_type,
                severity=severity,
                title=message[:255],
                description=message,
                user=user if user and user.is_authenticated else None,
                ip_address=client_ip,
                user_agent=user_agent,
                details=kwargs
            )
        
    except Exception as e:
        logger.error(f"Error logging security event: {e}")


def validate_file_upload(file):
    """
    Validate uploaded file for security threats.
    """
    # Maximum file size (10MB)
    max_size = 10 * 1024 * 1024
    
    if file.size > max_size:
        return False, "File size exceeds maximum allowed size (10MB)"
    
    # Allowed file extensions
    allowed_extensions = {
        '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        '.csv', '.txt', '.png', '.jpg', '.jpeg'
    }
    
    import os
    _, ext = os.path.splitext(file.name.lower())
    
    if ext not in allowed_extensions:
        return False, f"File type '{ext}' is not allowed"
    
    # Check MIME type
    allowed_mimes = {
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv',
        'text/plain',
        'image/png',
        'image/jpeg',
    }
    
    if hasattr(file, 'content_type') and file.content_type not in allowed_mimes:
        return False, f"MIME type '{file.content_type}' is not allowed"
    
    # Check for malicious content in filename
    if any(char in file.name for char in ['..', '/', '\\', '\x00']):
        return False, "Invalid characters in filename"
    
    return True, "File is valid"


def get_geoip_info(ip_address):
    """
    Get geographical information for an IP address.
    This is a placeholder - in production, integrate with a GeoIP service.
    """
    # TODO: Integrate with MaxMind GeoIP2 or similar service
    return {
        'country': 'Unknown',
        'country_code': 'XX',
        'city': 'Unknown',
        'region': 'Unknown',
        'timezone': 'UTC'
    }


def format_timedelta(td):
    """
    Format a timedelta object into a human-readable string.
    """
    total_seconds = int(td.total_seconds())
    
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or len(parts) == 0:
        parts.append(f"{minutes}m")
    
    return " ".join(parts)