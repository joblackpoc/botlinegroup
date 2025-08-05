# security_suite/signals.py

from django.db.models.signals import post_save, pre_save, post_delete
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.utils import timezone
from django.conf import settings
from ipware import get_client_ip
from .models import SecurityAlert, IPBlacklist, SessionMonitor
from .utils import log_security_event, get_geoip_info
from audit_trail.models import AuditLog
import logging

logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    """
    Signal handler for successful user login.
    """
    client_ip, _ = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    # Log successful login
    log_security_event(
        event_type='login',
        severity='info',
        message=f'User {user.email} logged in successfully',
        request=request,
        user=user
    )
    
    # Update user's last login IP and country
    if hasattr(user, 'last_login_ip'):
        user.last_login_ip = client_ip
    
    # Get geo info and update if available
    geo_info = get_geoip_info(client_ip)
    if hasattr(user, 'last_login_country'):
        user.last_login_country = geo_info.get('country_code', '')
    
    # Create or update session monitor
    if hasattr(request, 'session') and request.session.session_key:
        try:
            from .utils import hash_session_key
            session_monitor = SessionMonitor.objects.create(
                user=user,
                session_key_hash=hash_session_key(request.session.session_key),
                ip_address=client_ip,
                user_agent=user_agent,
                expires_at=request.session.get_expiry_date(),
                country=geo_info.get('country', ''),
                country_code=geo_info.get('country_code', ''),
                city=geo_info.get('city', ''),
                region=geo_info.get('region', ''),
                timezone_name=geo_info.get('timezone', '')
            )
            
            # Check for concurrent sessions
            active_sessions = SessionMonitor.objects.filter(
                user=user,
                terminated=False,
                expires_at__gt=timezone.now()
            ).count()
            
            if active_sessions > 3:  # Alert on too many concurrent sessions
                SecurityAlert.objects.create(
                    alert_type='suspicious_activity',
                    severity='medium',
                    title=f'Multiple concurrent sessions for {user.email}',
                    description=f'{active_sessions} active sessions detected',
                    user=user,
                    ip_address=client_ip,
                    details={
                        'session_count': active_sessions,
                        'latest_ip': client_ip,
                        'user_agent': user_agent
                    }
                )
        except Exception as e:
            logger.error(f"Error creating session monitor: {e}")


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    """
    Signal handler for user logout.
    """
    if user:
        log_security_event(
            event_type='logout',
            severity='info',
            message=f'User {user.email} logged out',
            request=request,
            user=user
        )
        
        # Terminate session monitor
        if hasattr(request, 'session') and request.session.session_key:
            try:
                from .utils import hash_session_key
                SessionMonitor.objects.filter(
                    session_key_hash=hash_session_key(request.session.session_key)
                ).update(
                    terminated=True,
                    terminated_at=timezone.now(),
                    termination_reason='User logout'
                )
            except Exception as e:
                logger.error(f"Error terminating session monitor: {e}")


@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """
    Signal handler for failed login attempts.
    """
    client_ip, _ = get_client_ip(request)
    username = credentials.get('username', 'unknown')
    
    # Log failed login
    log_security_event(
        event_type='login_failed',
        severity='warning',
        message=f'Failed login attempt for {username}',
        request=request,
        username=username
    )
    
    # Check for brute force patterns
    one_hour_ago = timezone.now() - timezone.timedelta(hours=1)
    
    # Count failed attempts from this IP
    failed_attempts = AuditLog.objects.filter(
        action='login_failed',
        ip_address=client_ip,
        timestamp__gte=one_hour_ago
    ).count()
    
    # Auto-blacklist after threshold
    if failed_attempts >= 20 and not IPBlacklist.objects.filter(
        ip_address=client_ip,
        is_active=True
    ).exists():
        
        blacklist = IPBlacklist.objects.create(
            ip_address=client_ip,
            reason='brute_force',
            description=f'Auto-blocked after {failed_attempts} failed login attempts',
            expires_at=timezone.now() + timezone.timedelta(hours=24),
            auto_blocked=True,
            threat_score=75.0
        )
        
        SecurityAlert.objects.create(
            alert_type='brute_force',
            severity='high',
            title=f'IP auto-blacklisted: {client_ip}',
            description=f'Blocked after {failed_attempts} failed login attempts',
            ip_address=client_ip,
            details={
                'failed_attempts': failed_attempts,
                'username_attempted': username,
                'block_duration': '24 hours'
            }
        )


@receiver(pre_save, sender=SecurityAlert)
def calculate_alert_risk_score(sender, instance, **kwargs):
    """
    Calculate risk score before saving alert.
    """
    if not instance.risk_score:
        instance.risk_score = instance.calculate_risk_score()


@receiver(post_save, sender=SecurityAlert)
def handle_critical_alerts(sender, instance, created, **kwargs):
    """
    Handle critical security alerts.
    """
    if created and instance.severity == 'critical':
        # Send immediate notification (implement your notification logic)
        try:
            from django.core.mail import mail_admins
            mail_admins(
                subject=f'CRITICAL Security Alert: {instance.title}',
                message=f"""
                Critical security alert created:
                
                Title: {instance.title}
                Type: {instance.get_alert_type_display()}
                Description: {instance.description}
                IP: {instance.ip_address or 'N/A'}
                User: {instance.user.email if instance.user else 'N/A'}
                Risk Score: {instance.risk_score}
                
                Please investigate immediately.
                """,
                fail_silently=True
            )
        except Exception as e:
            logger.error(f"Error sending critical alert notification: {e}")


@receiver(post_save, sender=IPBlacklist)
def log_ip_blacklist_changes(sender, instance, created, **kwargs):
    """
    Log IP blacklist changes.
    """
    if created:
        log_security_event(
            event_type='ip_blocked',
            severity='warning',
            message=f'IP blacklisted: {instance.ip_address}',
            ip_address=instance.ip_address,
            metadata={
                'reason': instance.reason,
                'auto_blocked': instance.auto_blocked,
                'expires_at': instance.expires_at.isoformat() if instance.expires_at else None
            }
        )


@receiver(pre_save, sender=SessionMonitor)
def calculate_session_risk(sender, instance, **kwargs):
    """
    Calculate session risk score before saving.
    """
    if not instance.pk:  # New session
        instance.risk_score = instance.calculate_risk_score()


@receiver(post_delete, sender=SessionMonitor)
def cleanup_session_data(sender, instance, **kwargs):
    """
    Clean up related data when session is deleted.
    """
    # Log session deletion
    logger.info(f"Session deleted for user {instance.user.email}: {instance.id}")


# Model-agnostic signal for audit logging
from django.db.models.signals import m2m_changed

AUDIT_MODELS = [
    'SecurityConfiguration',
    'ThreatIntelligence',
    'SecurityIncident',
    'ComplianceFramework'
]


@receiver(post_save)
def audit_model_changes(sender, instance, created, **kwargs):
    """
    Audit changes to security-related models.
    """
    model_name = sender.__name__
    
    if model_name in AUDIT_MODELS:
        action = 'created' if created else 'updated'
        
        # Get the user from the current request if available
        from django.contrib.auth.models import AnonymousUser
        user = None
        
        # Try to get user from instance
        if hasattr(instance, 'updated_by'):
            user = instance.updated_by
        elif hasattr(instance, 'created_by') and created:
            user = instance.created_by
        
        log_security_event(
            event_type='data_' + action,
            severity='info',
            message=f'{model_name} {action}: {str(instance)}',
            user=user,
            metadata={
                'model': model_name,
                'instance_id': str(instance.pk),
                'action': action
            }
        )


@receiver(post_delete)
def audit_model_deletion(sender, instance, **kwargs):
    """
    Audit deletion of security-related models.
    """
    model_name = sender.__name__
    
    if model_name in AUDIT_MODELS:
        log_security_event(
            event_type='data_deleted',
            severity='warning',
            message=f'{model_name} deleted: {str(instance)}',
            metadata={
                'model': model_name,
                'instance_id': str(instance.pk)
            }
        )