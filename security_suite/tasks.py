from celery import shared_task
from celery.utils.log import get_task_logger
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail, EmailMessage
from django.template.loader import render_to_string
from django.db.models import Count, Q, F, Avg
from django.db import transaction
from datetime import timedelta
import logging
import requests
from django.db import models
from .models import (
    SecurityAlert, IPBlacklist, SessionMonitor, 
    SecurityConfiguration, ThreatIntelligence,
    SecurityReport, SecurityIncident
)
from .utils import mask_email, log_security_event, get_geoip_info
from accounts.models import CustomUser
from audit_trail.models import AuditLog, PerformanceMetric, DataAccessLog
from django.contrib.sessions.models import Session
import csv
from io import StringIO
import json
from django.conf import settings

logger = get_task_logger(__name__)


@shared_task(bind=True, max_retries=3)
def cleanup_expired_sessions(self):
    """Clean up expired sessions from database and cache"""
    try:
        # Clean Django sessions
        expired_count = Session.objects.filter(expire_date__lt=timezone.now()).count()
        Session.objects.filter(expire_date__lt=timezone.now()).delete()
        
        # Clean our session monitors
        expired_sessions = SessionMonitor.objects.filter(
            expires_at__lt=timezone.now(),
            terminated=False
        )
        
        monitor_count = expired_sessions.count()
        
        # Batch update for performance
        with transaction.atomic():
            expired_sessions.update(
                terminated=True,
                terminated_at=timezone.now(),
                termination_reason='Session expired automatically'
            )
        
        logger.info(f"Cleaned up {expired_count} Django sessions and {monitor_count} monitored sessions")
        
        # Log the cleanup
        log_security_event(
            event_type='data_deleted',
            severity='info',
            message=f'Cleaned up {expired_count + monitor_count} expired sessions',
            metadata={
                'django_sessions': expired_count,
                'monitored_sessions': monitor_count
            }
        )
        
        return f"Cleaned up {expired_count + monitor_count} expired sessions"
        
    except Exception as e:
        logger.error(f"Error cleaning up sessions: {str(e)}")
        self.retry(exc=e, countdown=300)  # Retry in 5 minutes


@shared_task(bind=True, max_retries=3)
def run_security_audit(self):
    """Run comprehensive security audit with improved checks"""
    try:
        config = SecurityConfiguration.get_active_config()
        alerts_created = []
        
        with transaction.atomic():
            # Check for accounts with disabled MFA
            alerts_created.extend(_audit_mfa_compliance(config))
            
            # Check for expired passwords
            alerts_created.extend(_audit_password_expiry(config))
            
            # Check for inactive accounts
            alerts_created.extend(_audit_inactive_accounts())
            
            # Check for weak passwords (if password strength data available)
            alerts_created.extend(_audit_weak_passwords())
            
            # Check for excessive permissions
            alerts_created.extend(_audit_excessive_permissions())
        
        # Queue additional checks
        check_suspicious_login_patterns.delay()
        check_unusual_api_activity.delay()
        check_system_performance.delay()
        audit_session_anomalies.delay()
        
        logger.info(f"Security audit completed. Created {len(alerts_created)} alerts")
        
        # Log audit completion
        log_security_event(
            event_type='data_viewed',
            severity='info',
            message=f'Security audit completed with {len(alerts_created)} findings',
            metadata={'alerts_created': len(alerts_created)}
        )
        
        return f"Security audit completed. Created {len(alerts_created)} alerts"
        
    except Exception as e:
        logger.error(f"Error running security audit: {str(e)}")
        self.retry(exc=e, countdown=600)  # Retry in 10 minutes


def _audit_mfa_compliance(config):
    """Audit MFA compliance"""
    alerts = []
    
    users_without_mfa = CustomUser.objects.filter(
        is_active=True,
        mfa_enabled=False,
        last_login__isnull=False,
        is_superuser=False
    ).exclude(
        mfa_enforced_at__gte=timezone.now() - timedelta(days=config.mfa_grace_period_days)
    )
    
    if users_without_mfa.exists():
        # Group by risk level
        high_risk_users = users_without_mfa.filter(
            Q(is_staff=True) | Q(groups__name__in=['administrators', 'managers'])
        )
        
        if high_risk_users.exists():
            alert = SecurityAlert.objects.create(
                alert_type='mfa_bypass',
                severity='critical',
                title='High-risk users without MFA detected',
                description=f'{high_risk_users.count()} staff/admin users have not enabled MFA',
                details={
                    'user_count': high_risk_users.count(),
                    'users': [mask_email(u.email) for u in high_risk_users[:10]],
                    'risk_level': 'high'
                },
                risk_score=90.0
            )
            alerts.append(alert)
        
        # Regular users
        regular_users = users_without_mfa.exclude(
            Q(is_staff=True) | Q(groups__name__in=['administrators', 'managers'])
        )
        
        if regular_users.count() > 10:  # Only alert if significant number
            alert = SecurityAlert.objects.create(
                alert_type='mfa_bypass',
                severity='medium',
                title='Multiple users without MFA',
                description=f'{regular_users.count()} users have not enabled MFA',
                details={
                    'user_count': regular_users.count(),
                    'sample_users': [mask_email(u.email) for u in regular_users[:5]],
                    'risk_level': 'medium'
                },
                risk_score=50.0
            )
            alerts.append(alert)
    
    return alerts


def _audit_password_expiry(config):
    """Audit expired passwords"""
    alerts = []
    
    expiry_date = timezone.now() - timedelta(days=config.password_expiry_days)
    users_expired_passwords = CustomUser.objects.filter(
        is_active=True,
        last_password_change__lt=expiry_date
    )
    
    # Critical for admin accounts
    admin_expired = users_expired_passwords.filter(is_superuser=True)
    if admin_expired.exists():
        alert = SecurityAlert.objects.create(
            alert_type='expired_password',
            severity='critical',
            title='Admin accounts with expired passwords',
            description=f'{admin_expired.count()} admin accounts have expired passwords',
            details={
                'user_count': admin_expired.count(),
                'users': [mask_email(u.email) for u in admin_expired],
                'days_expired': config.password_expiry_days
            },
            risk_score=85.0
        )
        alerts.append(alert)
    
    # Regular users
    if users_expired_passwords.count() > 20:  # Alert threshold
        alert = SecurityAlert.objects.create(
            alert_type='expired_password',
            severity='medium',
            title='Multiple users with expired passwords',
            description=f'{users_expired_passwords.count()} users have expired passwords',
            details={
                'user_count': users_expired_passwords.count(),
                'sample_users': [mask_email(u.email) for u in users_expired_passwords[:10]],
                'days_expired': config.password_expiry_days
            },
            risk_score=60.0
        )
        alerts.append(alert)
    
    return alerts


def _audit_inactive_accounts():
    """Audit inactive accounts that should be disabled"""
    alerts = []
    
    # Accounts inactive for 90+ days
    inactive_date = timezone.now() - timedelta(days=90)
    inactive_users = CustomUser.objects.filter(
        is_active=True,
        last_login__lt=inactive_date
    )
    
    if inactive_users.count() > 5:
        alert = SecurityAlert.objects.create(
            alert_type='suspicious_activity',
            severity='low',
            title='Inactive accounts detected',
            description=f'{inactive_users.count()} accounts inactive for 90+ days',
            details={
                'user_count': inactive_users.count(),
                'sample_users': [mask_email(u.email) for u in inactive_users[:10]],
                'days_inactive': 90
            },
            risk_score=30.0
        )
        alerts.append(alert)
    
    return alerts


def _audit_weak_passwords():
    """Audit for weak passwords based on recent login patterns"""
    alerts = []
    
    # Check for accounts with multiple recent failed logins (possible weak password)
    recent_date = timezone.now() - timedelta(days=7)
    
    weak_password_candidates = AuditLog.objects.filter(
        action='login_failed',
        timestamp__gte=recent_date
    ).values('user').annotate(
        fail_count=Count('id')
    ).filter(fail_count__gte=10)
    
    if weak_password_candidates.exists():
        user_ids = [c['user'] for c in weak_password_candidates if c['user']]
        users = CustomUser.objects.filter(id__in=user_ids)
        
        alert = SecurityAlert.objects.create(
            alert_type='weak_password',
            severity='high',
            title='Possible weak passwords detected',
            description=f'{len(user_ids)} users with excessive failed login attempts',
            details={
                'user_count': len(user_ids),
                'users': [mask_email(u.email) for u in users[:10]],
                'threshold': 10,
                'period_days': 7
            },
            risk_score=70.0
        )
        alerts.append(alert)
    
    return alerts


def _audit_excessive_permissions():
    """Audit for users with excessive permissions"""
    alerts = []
    
    # Check for non-admin users with admin-like permissions
    dangerous_perms = [
        'delete_user', 'change_group', 'add_permission',
        'delete_securityalert', 'change_securityconfiguration'
    ]
    
    users_with_dangerous_perms = CustomUser.objects.filter(
        is_active=True,
        is_superuser=False,
        user_permissions__codename__in=dangerous_perms
    ).distinct()
    
    if users_with_dangerous_perms.exists():
        alert = SecurityAlert.objects.create(
            alert_type='privilege_escalation',
            severity='high',
            title='Non-admin users with dangerous permissions',
            description=f'{users_with_dangerous_perms.count()} users have elevated permissions',
            details={
                'user_count': users_with_dangerous_perms.count(),
                'users': [mask_email(u.email) for u in users_with_dangerous_perms[:10]],
                'permissions': dangerous_perms
            },
            risk_score=75.0
        )
        alerts.append(alert)
    
    return alerts

@shared_task(bind=True, max_retries=3)
def check_suspicious_login_patterns(self):
    """Enhanced detection of suspicious login patterns"""
    try:
        one_hour_ago = timezone.now() - timedelta(hours=1)
        alerts_created = []
        
        with transaction.atomic():
            # Brute force detection
            alerts_created.extend(_detect_brute_force(one_hour_ago))
            
            # Password spray detection
            alerts_created.extend(_detect_password_spray(one_hour_ago))
            
            # Geolocation anomalies
            alerts_created.extend(_detect_location_anomalies(one_hour_ago))
            
            # Impossible travel detection
            alerts_created.extend(_detect_impossible_travel())
        
        logger.info(f"Suspicious login check completed. Created {len(alerts_created)} alerts")
        return f"Created {len(alerts_created)} suspicious login alerts"
        
    except Exception as e:
        logger.error(f"Error checking suspicious login patterns: {str(e)}")
        self.retry(exc=e, countdown=300)

def _detect_brute_force(since_time):
    """Detect brute force attacks"""
    alerts = []
    
    # Failed logins by IP
    failed_by_ip = AuditLog.objects.filter(
        action='login_failed',
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        count=Count('id'),
        unique_users=Count('user', distinct=True)
    ).filter(count__gte=10)
    
    for entry in failed_by_ip:
        # Skip if already blacklisted
        if IPBlacklist.objects.filter(
            ip_address=entry['ip_address'],
            is_active=True
        ).exists():
            continue
        
        severity = 'critical' if entry['count'] >= 50 else 'high'
        
        alert = SecurityAlert.objects.create(
            alert_type='brute_force',
            severity=severity,
            title=f'Brute force attack from {entry["ip_address"]}',
            description=f'{entry["count"]} failed login attempts targeting {entry["unique_users"]} users',
            ip_address=entry['ip_address'],
            details={
                'failed_attempts': entry['count'],
                'unique_users_targeted': entry['unique_users'],
                'time_period': '1 hour',
                'attack_pattern': 'brute_force'
            },
            risk_score=90.0 if severity == 'critical' else 75.0
        )
        alerts.append(alert)
        
        # Auto-blacklist severe attacks
        if entry['count'] >= 50:
            IPBlacklist.objects.create(
                ip_address=entry['ip_address'],
                reason='brute_force',
                description=f'Auto-blocked: {entry["count"]} failed attempts in 1 hour',
                expires_at=timezone.now() + timedelta(hours=24),
                auto_blocked=True,
                threat_score=90.0
            )
    
    return alerts


def _detect_password_spray(since_time):
    """Detect password spray attacks"""
    alerts = []
    
    # Multiple IPs targeting same user
    targeted_users = AuditLog.objects.filter(
        action='login_failed',
        timestamp__gte=since_time,
        user__isnull=False
    ).values('user').annotate(
        unique_ips=Count('ip_address', distinct=True),
        total_attempts=Count('id')
    ).filter(unique_ips__gte=5)
    
    for entry in targeted_users:
        try:
            user = CustomUser.objects.get(id=entry['user'])
            
            alert = SecurityAlert.objects.create(
                alert_type='password_spray',
                severity='critical',
                title=f'Password spray attack targeting {mask_email(user.email)}',
                description=f'Failed logins from {entry["unique_ips"]} different IPs',
                user=user,
                details={
                    'unique_ip_count': entry['unique_ips'],
                    'total_attempts': entry['total_attempts'],
                    'time_period': '1 hour',
                    'attack_pattern': 'password_spray'
                },
                risk_score=85.0
            )
            alerts.append(alert)
            
            # Lock account if too many attempts
            if entry['total_attempts'] >= 50:
                user.is_active = False
                user.save()
                
                SecurityAlert.objects.create(
                    alert_type='account_lockout',
                    severity='high',
                    title=f'Account locked due to password spray attack',
                    description=f'Account {mask_email(user.email)} locked after {entry["total_attempts"]} attempts',
                    user=user,
                    details={
                        'reason': 'password_spray_protection',
                        'attempts': entry['total_attempts']
                    }
                )
                
        except CustomUser.DoesNotExist:
            continue
    
    return alerts


def _detect_location_anomalies(since_time):
    """Detect login location anomalies"""
    alerts = []
    
    # Get recent successful logins
    recent_logins = AuditLog.objects.filter(
        action='login',
        timestamp__gte=since_time
    ).select_related('user')
    
    for login in recent_logins:
        if not login.user:
            continue
        
        # Get user's login history
        previous_logins = AuditLog.objects.filter(
            action='login',
            user=login.user,
            timestamp__lt=login.timestamp,
            timestamp__gte=login.timestamp - timedelta(days=30)
        ).values_list('ip_address', flat=True).distinct()
        
        if previous_logins:
            # Simple check: new IP not in recent history
            if login.ip_address not in previous_logins:
                # Get geo info (placeholder - implement actual GeoIP)
                current_geo = get_geoip_info(login.ip_address)
                
                alert = SecurityAlert.objects.create(
                    alert_type='suspicious_activity',
                    severity='medium',
                    title=f'Login from new location for {mask_email(login.user.email)}',
                    description=f'Login from {current_geo["country"]} ({login.ip_address})',
                    user=login.user,
                    ip_address=login.ip_address,
                    details={
                        'new_location': current_geo,
                        'known_ips': len(previous_logins),
                        'risk_factor': 'new_location'
                    },
                    risk_score=45.0
                )
                alerts.append(alert)
    
    return alerts


def _detect_impossible_travel():
    """Detect impossible travel scenarios"""
    alerts = []
    
    # Look for users with logins from different locations in short time
    two_hours_ago = timezone.now() - timedelta(hours=2)
    
    users_with_multiple_logins = AuditLog.objects.filter(
        action='login',
        timestamp__gte=two_hours_ago
    ).values('user').annotate(
        login_count=Count('id'),
        unique_ips=Count('ip_address', distinct=True)
    ).filter(login_count__gte=2, unique_ips__gte=2)
    
    for entry in users_with_multiple_logins:
        if not entry['user']:
            continue
        
        # Get the login details
        user_logins = AuditLog.objects.filter(
            action='login',
            user_id=entry['user'],
            timestamp__gte=two_hours_ago
        ).order_by('timestamp').values('timestamp', 'ip_address')
        
        # Check for impossible travel (simplified - would need real geo data)
        logins_list = list(user_logins)
        for i in range(len(logins_list) - 1):
            time_diff = (logins_list[i+1]['timestamp'] - logins_list[i]['timestamp']).total_seconds() / 3600
            
            # If different IPs within 1 hour (impossible travel threshold)
            if (logins_list[i]['ip_address'] != logins_list[i+1]['ip_address'] and 
                time_diff < 1.0):
                
                try:
                    user = CustomUser.objects.get(id=entry['user'])
                    
                    alert = SecurityAlert.objects.create(
                        alert_type='suspicious_activity',
                        severity='high',
                        title=f'Impossible travel detected for {mask_email(user.email)}',
                        description=f'Logins from different locations within {time_diff:.1f} hours',
                        user=user,
                        details={
                            'ip1': logins_list[i]['ip_address'],
                            'ip2': logins_list[i+1]['ip_address'],
                            'time_difference_hours': time_diff,
                            'risk_factor': 'impossible_travel'
                        },
                        risk_score=80.0
                    )
                    alerts.append(alert)
                    break
                    
                except CustomUser.DoesNotExist:
                    continue
    
    return alerts


@shared_task(bind=True, max_retries=3)
def check_unusual_api_activity(self):
    """Enhanced monitoring for unusual API activity patterns"""
    try:
        one_hour_ago = timezone.now() - timedelta(hours=1)
        alerts_created = []
        
        with transaction.atomic():
            # Rate limit violations
            alerts_created.extend(_detect_rate_limit_abuse(one_hour_ago))
            
            # Data exfiltration patterns
            alerts_created.extend(_detect_data_exfiltration(one_hour_ago))
            
            # API scanning/enumeration
            alerts_created.extend(_detect_api_scanning(one_hour_ago))
            
            # Unusual access patterns
            alerts_created.extend(_detect_unusual_access_patterns(one_hour_ago))
        
        logger.info(f"API activity check completed. Created {len(alerts_created)} alerts")
        return f"Created {len(alerts_created)} API activity alerts"
        
    except Exception as e:
        logger.error(f"Error checking unusual API activity: {str(e)}")
        self.retry(exc=e, countdown=300)


def _detect_rate_limit_abuse(since_time):
    """Detect rate limit abuse"""
    alerts = []
    config = SecurityConfiguration.get_active_config()
    
    # High volume API calls
    high_volume = AuditLog.objects.filter(
        timestamp__gte=since_time
    ).exclude(
        action__in=['login', 'logout', 'login_failed']
    ).values('user', 'ip_address').annotate(
        api_calls=Count('id')
    ).filter(api_calls__gte=config.rate_limit_requests)
    
    for entry in high_volume:
        title_parts = []
        details = {'api_calls': entry['api_calls'], 'time_period': '1 hour'}
        
        if entry['user']:
            try:
                user = CustomUser.objects.get(id=entry['user'])
                title_parts.append(f'user {mask_email(user.email)}')
                details['user'] = mask_email(user.email)
                alert_user = user
            except CustomUser.DoesNotExist:
                alert_user = None
        else:
            alert_user = None
        
        if entry['ip_address']:
            title_parts.append(f'IP {entry["ip_address"]}')
            details['ip_address'] = entry['ip_address']
            alert_ip = entry['ip_address']
        else:
            alert_ip = None
        
        if title_parts:
            alert = SecurityAlert.objects.create(
                alert_type='rate_limit',
                severity='medium',
                title=f'High API usage from {" and ".join(title_parts)}',
                description=f'{entry["api_calls"]} API calls in the last hour',
                user=alert_user,
                ip_address=alert_ip,
                details=details,
                risk_score=55.0
            )
            alerts.append(alert)
    
    return alerts


def _detect_data_exfiltration(since_time):
    """Detect potential data exfiltration"""
    alerts = []
    
    # Large number of data access operations
    data_access = AuditLog.objects.filter(
        action__in=['data_viewed', 'data_exported'],
        timestamp__gte=since_time
    ).values('user').annotate(
        access_count=Count('id'),
        unique_resources=Count('resource_id', distinct=True)
    ).filter(access_count__gte=100)
    
    for entry in data_access:
        if not entry['user']:
            continue
        
        try:
            user = CustomUser.objects.get(id=entry['user'])
            
            # Check if this is unusual for the user
            historical_avg = AuditLog.objects.filter(
                user=user,
                action__in=['data_viewed', 'data_exported'],
                timestamp__lt=since_time,
                timestamp__gte=since_time - timedelta(days=7)
            ).count() / 7 / 24  # Average per hour over last week
            
            if entry['access_count'] > historical_avg * 10:  # 10x normal rate
                alert = SecurityAlert.objects.create(
                    alert_type='data_exfiltration',
                    severity='high',
                    title=f'Possible data exfiltration by {mask_email(user.email)}',
                    description=f'{entry["access_count"]} data operations on {entry["unique_resources"]} resources',
                    user=user,
                    details={
                        'access_count': entry['access_count'],
                        'unique_resources': entry['unique_resources'],
                        'historical_avg_hourly': round(historical_avg, 2),
                        'multiplication_factor': round(entry['access_count'] / max(historical_avg, 1), 1)
                    },
                    risk_score=75.0
                )
                alerts.append(alert)
                
        except CustomUser.DoesNotExist:
            continue
    
    return alerts


def _detect_api_scanning(since_time):
    """Detect API enumeration/scanning attempts"""
    alerts = []
    
    # Look for 404s and 403s patterns
    scanning_patterns = AuditLog.objects.filter(
        action__in=['unauthorized_access', 'data_viewed'],
        severity__in=['warning', 'error'],
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        error_count=Count('id'),
        unique_paths=Count('metadata__path', distinct=True)
    ).filter(error_count__gte=50, unique_paths__gte=20)
    
    for entry in scanning_patterns:
        if not entry['ip_address']:
            continue
        
        alert = SecurityAlert.objects.create(
            alert_type='suspicious_activity',
            severity='high',
            title=f'API scanning detected from {entry["ip_address"]}',
            description=f'{entry["error_count"]} failed requests to {entry["unique_paths"]} different endpoints',
            ip_address=entry['ip_address'],
            details={
                'error_count': entry['error_count'],
                'unique_paths': entry['unique_paths'],
                'attack_pattern': 'api_enumeration'
            },
            risk_score=70.0
        )
        alerts.append(alert)
        
        # Auto-blacklist scanners
        if entry['error_count'] >= 100:
            IPBlacklist.objects.get_or_create(
                ip_address=entry['ip_address'],
                defaults={
                    'reason': 'vulnerability_scan',
                    'description': f'Auto-blocked: API scanning with {entry["error_count"]} attempts',
                    'expires_at': timezone.now() + timedelta(days=7),
                    'auto_blocked': True,
                    'threat_score': 75.0
                }
            )
    
    return alerts


def _detect_unusual_access_patterns(since_time):
    """Detect unusual data access patterns"""
    alerts = []
    
    # Night time access (assuming most users work 9-5)
    current_hour = timezone.now().hour
    if 0 <= current_hour <= 6:  # Night hours
        night_access = AuditLog.objects.filter(
            action='data_viewed',
            timestamp__gte=since_time,
            user__isnull=False
        ).values('user').annotate(
            access_count=Count('id')
        ).filter(access_count__gte=20)
        
        for entry in night_access:
            try:
                user = CustomUser.objects.get(id=entry['user'])
                
                # Check if user normally works at night
                historical_night = AuditLog.objects.filter(
                    user=user,
                    timestamp__hour__gte=0,
                    timestamp__hour__lte=6,
                    timestamp__gte=timezone.now() - timedelta(days=30)
                ).count()
                
                if historical_night < 10:  # Not a night worker
                    alert = SecurityAlert.objects.create(
                        alert_type='suspicious_activity',
                        severity='medium',
                        title=f'Unusual night access by {mask_email(user.email)}',
                        description=f'{entry["access_count"]} data accesses during night hours',
                        user=user,
                        details={
                            'access_count': entry['access_count'],
                            'time_period': 'night',
                            'local_hour': current_hour,
                            'historical_night_activity': historical_night
                        },
                        risk_score=50.0
                    )
                    alerts.append(alert)
                    
            except CustomUser.DoesNotExist:
                continue
    
    return alerts


@shared_task(bind=True, max_retries=3)
def check_system_performance(self):
    """Enhanced system performance monitoring"""
    try:
        one_hour_ago = timezone.now() - timedelta(hours=1)
        alerts_created = []
        
        # Response time analysis
        response_metrics = PerformanceMetric.objects.filter(
            metric_type='response_time',
            timestamp__gte=one_hour_ago
        ).aggregate(
            avg_time=Avg('value'),
            max_time=models.Max('value'),
            count=Count('id')
        )
        
        if response_metrics['avg_time'] and response_metrics['avg_time'] > 1000:
            alert = SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='medium',
                title='High average response time detected',
                description=f'Average response time is {response_metrics["avg_time"]:.2f}ms',
                details={
                    'avg_response_time': response_metrics['avg_time'],
                    'max_response_time': response_metrics['max_time'],
                    'request_count': response_metrics['count'],
                    'threshold': 1000,
                    'time_period': '1 hour'
                },
                risk_score=40.0
            )
            alerts_created.append(alert)
        
        # Error rate analysis
        error_metrics = self._analyze_error_rates(one_hour_ago)
        if error_metrics['alert_needed']:
            alert = SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='high',
                title='High error rate detected',
                description=f'Error rate is {error_metrics["error_rate"]:.2f}%',
                details=error_metrics,
                risk_score=65.0
            )
            alerts_created.append(alert)
        
        # Resource usage (placeholder for actual monitoring)
        self._check_resource_usage()
        
        logger.info(f"System performance check completed. Created {len(alerts_created)} alerts")
        return f"Created {len(alerts_created)} performance alerts"
        
    except Exception as e:
        logger.error(f"Error checking system performance: {str(e)}")
        self.retry(exc=e, countdown=300)


def _analyze_error_rates(since_time):
    """Analyze error rates"""
    total_requests = PerformanceMetric.objects.filter(
        metric_type='response_time',
        timestamp__gte=since_time
    ).count()
    
    error_requests = PerformanceMetric.objects.filter(
        metric_type='error_rate',
        timestamp__gte=since_time
    ).count()
    
    if total_requests > 0:
        error_rate = (error_requests / total_requests) * 100
        
        return {
            'error_rate': error_rate,
            'error_count': error_requests,
            'total_requests': total_requests,
            'threshold': 5,
            'alert_needed': error_rate > 5
        }
    
    return {'alert_needed': False}


def _check_resource_usage():
    """Check system resource usage (CPU, memory, disk)"""
    # This would integrate with system monitoring tools
    # For now, it's a placeholder
    pass


@shared_task(bind=True, max_retries=3)
def audit_session_anomalies(self):
    """Audit for session anomalies"""
    try:
        alerts_created = []
        
        # Multiple concurrent sessions
        concurrent_sessions = SessionMonitor.objects.filter(
            terminated=False,
            expires_at__gt=timezone.now()
        ).values('user').annotate(
            session_count=Count('id'),
            unique_ips=Count('ip_address', distinct=True)
        ).filter(session_count__gt=3)
        
        for entry in concurrent_sessions:
            try:
                user = CustomUser.objects.get(id=entry['user'])
                
                alert = SecurityAlert.objects.create(
                    alert_type='session_hijack',
                    severity='medium',
                    title=f'Multiple concurrent sessions for {mask_email(user.email)}',
                    description=f'{entry["session_count"]} active sessions from {entry["unique_ips"]} IPs',
                    user=user,
                    details={
                        'session_count': entry['session_count'],
                        'unique_ips': entry['unique_ips'],
                        'risk_factor': 'concurrent_sessions'
                    },
                    risk_score=55.0
                )
                alerts_created.append(alert)
                
            except CustomUser.DoesNotExist:
                continue
        
        # Long-running sessions
        long_session_threshold = timezone.now() - timedelta(hours=24)
        long_sessions = SessionMonitor.objects.filter(
            terminated=False,
            created_at__lt=long_session_threshold
        )
        
        for session in long_sessions:
            alert = SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='low',
                title=f'Long-running session detected for {mask_email(session.user.email)}',
                description=f'Session active for over 24 hours',
                user=session.user,
                ip_address=session.ip_address,
                details={
                    'session_id': str(session.id),
                    'duration_hours': (timezone.now() - session.created_at).total_seconds() / 3600,
                    'risk_factor': 'long_session'
                },
                risk_score=35.0
            )
            alerts_created.append(alert)
        
        logger.info(f"Session anomaly audit completed. Created {len(alerts_created)} alerts")
        return f"Created {len(alerts_created)} session anomaly alerts"
        
    except Exception as e:
        logger.error(f"Error auditing session anomalies: {str(e)}")
        self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def update_threat_intelligence(self):
    """Update threat intelligence from external sources"""
    try:
        updated_count = 0
        
        # Update from configured threat feeds
        threat_feeds = getattr(settings, 'THREAT_INTELLIGENCE_FEEDS', [])
        
        for feed in threat_feeds:
            try:
                if feed['type'] == 'ip_blacklist':
                    updated_count += self._update_ip_blacklist(feed)
                elif feed['type'] == 'domain_blacklist':
                    updated_count += self._update_domain_blacklist(feed)
                elif feed['type'] == 'hash_list':
                    updated_count += self._update_hash_list(feed)
            except Exception as e:
                logger.error(f"Error updating from feed {feed['name']}: {e}")
        
        # Update threat scores based on hits
        self._update_threat_scores()
        
        # Clean up expired entries
        expired = ThreatIntelligence.objects.filter(
            expires_at__lt=timezone.now()
        ).update(is_active=False)
        
        logger.info(f"Threat intelligence update completed. Updated {updated_count} entries, expired {expired}")
        return f"Updated {updated_count} threat intelligence entries"
        
    except Exception as e:
        logger.error(f"Error updating threat intelligence: {str(e)}")
        self.retry(exc=e, countdown=3600)  # Retry in 1 hour


def _update_ip_blacklist(self, feed):
    """Update IP blacklist from feed"""
    updated = 0
    
    try:
        response = requests.get(feed['url'], timeout=30)
        response.raise_for_status()
        
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse IP address (simple format assumed)
                ip = line.split()[0]
                
                threat, created = ThreatIntelligence.objects.update_or_create(
                    threat_type='ip',
                    threat_value=ip,
                    defaults={
                        'threat_level': feed.get('default_level', 'medium'),
                        'threat_category': feed.get('category', 'malware'),
                        'description': f'IP from {feed["name"]} feed',
                        'source': feed['name'],
                        'source_url': feed['url'],
                        'confidence': feed.get('confidence', 75),
                        'expires_at': timezone.now() + timedelta(days=7),
                        'is_active': True
                    }
                )
                
                if created:
                    updated += 1
                else:
                    threat.last_seen = timezone.now()
                    threat.save()
    
    except Exception as e:
        logger.error(f"Error updating IP blacklist from {feed['name']}: {e}")
    
    return updated


def _update_domain_blacklist(self, feed):
    """Update domain blacklist from feed"""
    # Similar implementation to IP blacklist
    return 0


def _update_hash_list(self, feed):
    """Update hash list from feed"""
    # Similar implementation to IP blacklist
    return 0


def _update_threat_scores(self):
    """Update threat scores based on activity"""
    # Update scores for frequently hit threats
    high_hit_threats = ThreatIntelligence.objects.filter(
        hit_count__gte=10,
        is_active=True
    )
    
    for threat in high_hit_threats:
        threat.severity_score = min(threat.severity_score * 1.1, 100.0)
        threat.save()


@shared_task(bind=True, max_retries=3)
def generate_daily_security_report(self):
    """Generate and email enhanced daily security report"""
    try:
        yesterday = timezone.now() - timedelta(days=1)
        today = timezone.now()
        
        # Comprehensive statistics
        stats = {
            'date': yesterday.date(),
            'total_logins': AuditLog.objects.filter(
                action='login',
                timestamp__date=yesterday.date()
            ).count(),
            'failed_logins': AuditLog.objects.filter(
                action='login_failed',
                timestamp__date=yesterday.date()
            ).count(),
            'unique_users': AuditLog.objects.filter(
                action='login',
                timestamp__date=yesterday.date()
            ).values('user').distinct().count(),
            'new_alerts': SecurityAlert.objects.filter(
                created_at__date=yesterday.date()
            ).count(),
            'critical_alerts': SecurityAlert.objects.filter(
                created_at__date=yesterday.date(),
                severity='critical'
            ).count(),
            'resolved_alerts': SecurityAlert.objects.filter(
                resolved_at__date=yesterday.date()
            ).count(),
            'blocked_ips': IPBlacklist.objects.filter(
                blocked_at__date=yesterday.date()
            ).count(),
            'active_users': CustomUser.objects.filter(
                last_activity__date=yesterday.date()
            ).count(),
            'new_threats': ThreatIntelligence.objects.filter(
                first_seen__date=yesterday.date()
            ).count(),
        }
        
        # Calculate trends
        prev_day = yesterday - timedelta(days=1)
        prev_stats = {
            'total_logins': AuditLog.objects.filter(
                action='login',
                timestamp__date=prev_day.date()
            ).count(),
            'failed_logins': AuditLog.objects.filter(
                action='login_failed',
                timestamp__date=prev_day.date()
            ).count(),
        }
        
        trends = {
            'login_trend': self._calculate_trend(stats['total_logins'], prev_stats['total_logins']),
            'failed_login_trend': self._calculate_trend(stats['failed_logins'], prev_stats['failed_logins']),
        }
        
        # Get top alerts
        top_alerts = SecurityAlert.objects.filter(
            created_at__date=yesterday.date()
        ).order_by('-severity', '-risk_score', '-created_at')[:10]
        
        # Get top threats
        top_threats = AuditLog.objects.filter(
            action__in=['login_failed', 'unauthorized_access'],
            timestamp__date=yesterday.date()
        ).values('ip_address').annotate(
            threat_count=Count('id')
        ).order_by('-threat_count')[:5]
        
        # Security score calculation
        security_score = self._calculate_security_score(stats)
        
        # Send to admins and security team
        recipients = list(CustomUser.objects.filter(
            Q(is_superuser=True) | Q(groups__name='security_team'),
            is_active=True
        ).values_list('email', flat=True).distinct())
        
        if recipients:
            html_content = render_to_string('emails/daily_security_report.html', {
                'stats': stats,
                'trends': trends,
                'top_alerts': top_alerts,
                'top_threats': top_threats,
                'security_score': security_score,
                'report_date': yesterday.date(),
            })
            
            email = EmailMessage(
                subject=f'Daily Security Report - {yesterday.date()} - Score: {security_score}/100',
                body=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=recipients,
            )
            email.content_subtype = 'html'
            
            # Attach CSV summary
            csv_content = self._generate_report_csv(stats, top_alerts, top_threats)
            email.attach(
                f'security_summary_{yesterday.date()}.csv',
                csv_content,
                'text/csv'
            )
            
            email.send()
            
            logger.info(f"Daily security report sent to {len(recipients)} recipients")
        
        return f"Report sent to {len(recipients)} recipients"
        
    except Exception as e:
        logger.error(f"Error generating daily security report: {str(e)}")
        self.retry(exc=e, countdown=3600)


def _calculate_trend(self, current, previous):
    """Calculate percentage trend"""
    if previous == 0:
        return 100 if current > 0 else 0
    return round(((current - previous) / previous) * 100, 1)

def _calculate_security_score(self, stats):
    """Calculate overall security score (0-100)"""
    score = 100
    self.retry(exc=e, countdown=300)

def _detect_brute_force(since_time):
    """Detect brute force attacks"""
    alerts = []
    
    # Failed logins by IP
    failed_by_ip = AuditLog.objects.filter(
        action='login_failed',
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        count=Count('id'),
        unique_users=Count('user', distinct=True)
    ).filter(count__gte=10)
    
    for entry in failed_by_ip:
        # Skip if already blacklisted
        if IPBlacklist.objects.filter(
            ip_address=entry['ip_address'],
            is_active=True
        ).exists():
            continue
        
        severity = 'critical' if entry['count'] >= 50 else 'high'
        
        alert = SecurityAlert.objects.create(
            alert_type='brute_force',
            severity=severity,
            title=f'Brute force attack from {entry["ip_address"]}',
            description=f'{entry["count"]} failed login attempts targeting {entry["unique_users"]} users',
            ip_address=entry['ip_address'],
            details={
                'failed_attempts': entry['count'],
                'unique_users_targeted': entry['unique_users'],
                'time_period': '1 hour',
                'attack_pattern': 'brute_force'
            },
            risk_score=90.0 if severity == 'critical' else 75.0
        )
        alerts.append(alert)
        
        # Auto-blacklist severe attacks
        if entry['count'] >= 50:
            IPBlacklist.objects.create(
                ip_address=entry['ip_address'],
                reason='brute_force',
                description=f'Auto-blocked: {entry["count"]} failed attempts in 1 hour',
                expires_at=timezone.now() + timedelta(hours=24),
                auto_blocked=True,
                threat_score=90.0
            )
    
    return alerts


def _detect_password_spray(since_time):
    """Detect password spray attacks"""
    alerts = []
    
    # Multiple IPs targeting same user
    targeted_users = AuditLog.objects.filter(
        action='login_failed',
        timestamp__gte=since_time,
        user__isnull=False
    ).values('user').annotate(
        unique_ips=Count('ip_address', distinct=True),
        total_attempts=Count('id')
    ).filter(unique_ips__gte=5)
    
    for entry in targeted_users:
        try:
            user = CustomUser.objects.get(id=entry['user'])
            
            alert = SecurityAlert.objects.create(
                alert_type='password_spray',
                severity='critical',
                title=f'Password spray attack targeting {mask_email(user.email)}',
                description=f'Failed logins from {entry["unique_ips"]} different IPs',
                user=user,
                details={
                    'unique_ip_count': entry['unique_ips'],
                    'total_attempts': entry['total_attempts'],
                    'time_period': '1 hour',
                    'attack_pattern': 'password_spray'
                },
                risk_score=85.0
            )
            alerts.append(alert)
            
            # Lock account if too many attempts
            if entry['total_attempts'] >= 50:
                user.is_active = False
                user.save()
                
                SecurityAlert.objects.create(
                    alert_type='account_lockout',
                    severity='high',
                    title=f'Account locked due to password spray attack',
                    description=f'Account {mask_email(user.email)} locked after {entry["total_attempts"]} attempts',
                    user=user,
                    details={
                        'reason': 'password_spray_protection',
                        'attempts': entry['total_attempts']
                    }
                )
                
        except CustomUser.DoesNotExist:
            continue
    
    return alerts


def _detect_location_anomalies(since_time):
    """Detect login location anomalies"""
    alerts = []
    
    # Get recent successful logins
    recent_logins = AuditLog.objects.filter(
        action='login',
        timestamp__gte=since_time
    ).select_related('user')
    
    for login in recent_logins:
        if not login.user:
            continue
        
        # Get user's login history
        previous_logins = AuditLog.objects.filter(
            action='login',
            user=login.user,
            timestamp__lt=login.timestamp,
            timestamp__gte=login.timestamp - timedelta(days=30)
        ).values_list('ip_address', flat=True).distinct()
        
        if previous_logins:
            # Simple check: new IP not in recent history
            if login.ip_address not in previous_logins:
                # Get geo info (placeholder - implement actual GeoIP)
                current_geo = get_geoip_info(login.ip_address)
                
                alert = SecurityAlert.objects.create(
                    alert_type='suspicious_activity',
                    severity='medium',
                    title=f'Login from new location for {mask_email(login.user.email)}',
                    description=f'Login from {current_geo["country"]} ({login.ip_address})',
                    user=login.user,
                    ip_address=login.ip_address,
                    details={
                        'new_location': current_geo,
                        'known_ips': len(previous_logins),
                        'risk_factor': 'new_location'
                    },
                    risk_score=45.0
                )
                alerts.append(alert)
    
    return alerts


def _detect_impossible_travel():
    """Detect impossible travel scenarios"""
    alerts = []
    
    # Look for users with logins from different locations in short time
    two_hours_ago = timezone.now() - timedelta(hours=2)
    
    users_with_multiple_logins = AuditLog.objects.filter(
        action='login',
        timestamp__gte=two_hours_ago
    ).values('user').annotate(
        login_count=Count('id'),
        unique_ips=Count('ip_address', distinct=True)
    ).filter(login_count__gte=2, unique_ips__gte=2)
    
    for entry in users_with_multiple_logins:
        if not entry['user']:
            continue
        
        # Get the login details
        user_logins = AuditLog.objects.filter(
            action='login',
            user_id=entry['user'],
            timestamp__gte=two_hours_ago
        ).order_by('timestamp').values('timestamp', 'ip_address')
        
        # Check for impossible travel (simplified - would need real geo data)
        logins_list = list(user_logins)
        for i in range(len(logins_list) - 1):
            time_diff = (logins_list[i+1]['timestamp'] - logins_list[i]['timestamp']).total_seconds() / 3600
            
            # If different IPs within 1 hour (impossible travel threshold)
            if (logins_list[i]['ip_address'] != logins_list[i+1]['ip_address'] and 
                time_diff < 1.0):
                
                try:
                    user = CustomUser.objects.get(id=entry['user'])
                    
                    alert = SecurityAlert.objects.create(
                        alert_type='suspicious_activity',
                        severity='high',
                        title=f'Impossible travel detected for {mask_email(user.email)}',
                        description=f'Logins from different locations within {time_diff:.1f} hours',
                        user=user,
                        details={
                            'ip1': logins_list[i]['ip_address'],
                            'ip2': logins_list[i+1]['ip_address'],
                            'time_difference_hours': time_diff,
                            'risk_factor': 'impossible_travel'
                        },
                        risk_score=80.0
                    )
                    alerts.append(alert)
                    break
                    
                except CustomUser.DoesNotExist:
                    continue
    
    return alerts


@shared_task(bind=True, max_retries=3)
def check_unusual_api_activity(self):
    """Enhanced monitoring for unusual API activity patterns"""
    try:
        one_hour_ago = timezone.now() - timedelta(hours=1)
        alerts_created = []
        
        with transaction.atomic():
            # Rate limit violations
            alerts_created.extend(_detect_rate_limit_abuse(one_hour_ago))
            
            # Data exfiltration patterns
            alerts_created.extend(_detect_data_exfiltration(one_hour_ago))
            
            # API scanning/enumeration
            alerts_created.extend(_detect_api_scanning(one_hour_ago))
            
            # Unusual access patterns
            alerts_created.extend(_detect_unusual_access_patterns(one_hour_ago))
        
        logger.info(f"API activity check completed. Created {len(alerts_created)} alerts")
        return f"Created {len(alerts_created)} API activity alerts"
        
    except Exception as e:
        logger.error(f"Error checking unusual API activity: {str(e)}")
        self.retry(exc=e, countdown=300)


def _detect_rate_limit_abuse(since_time):
    """Detect rate limit abuse"""
    alerts = []
    config = SecurityConfiguration.get_active_config()
    
    # High volume API calls
    high_volume = AuditLog.objects.filter(
        timestamp__gte=since_time
    ).exclude(
        action__in=['login', 'logout', 'login_failed']
    ).values('user', 'ip_address').annotate(
        api_calls=Count('id')
    ).filter(api_calls__gte=config.rate_limit_requests)
    
    for entry in high_volume:
        title_parts = []
        details = {'api_calls': entry['api_calls'], 'time_period': '1 hour'}
        
        if entry['user']:
            try:
                user = CustomUser.objects.get(id=entry['user'])
                title_parts.append(f'user {mask_email(user.email)}')
                details['user'] = mask_email(user.email)
                alert_user = user
            except CustomUser.DoesNotExist:
                alert_user = None
        else:
            alert_user = None
        
        if entry['ip_address']:
            title_parts.append(f'IP {entry["ip_address"]}')
            details['ip_address'] = entry['ip_address']
            alert_ip = entry['ip_address']
        else:
            alert_ip = None
        
        if title_parts:
            alert = SecurityAlert.objects.create(
                alert_type='rate_limit',
                severity='medium',
                title=f'High API usage from {" and ".join(title_parts)}',
                description=f'{entry["api_calls"]} API calls in the last hour',
                user=alert_user,
                ip_address=alert_ip,
                details=details,
                risk_score=55.0
            )
            alerts.append(alert)
    
    return alerts


def _detect_data_exfiltration(since_time):
    """Detect potential data exfiltration"""
    alerts = []
    
    # Large number of data access operations
    data_access = AuditLog.objects.filter(
        action__in=['data_viewed', 'data_exported'],
        timestamp__gte=since_time
    ).values('user').annotate(
        access_count=Count('id'),
        unique_resources=Count('resource_id', distinct=True)
    ).filter(access_count__gte=100)
    
    for entry in data_access:
        if not entry['user']:
            continue
        
        try:
            user = CustomUser.objects.get(id=entry['user'])
            
            # Check if this is unusual for the user
            historical_avg = AuditLog.objects.filter(
                user=user,
                action__in=['data_viewed', 'data_exported'],
                timestamp__lt=since_time,
                timestamp__gte=since_time - timedelta(days=7)
            ).count() / 7 / 24  # Average per hour over last week
            
            if entry['access_count'] > historical_avg * 10:  # 10x normal rate
                alert = SecurityAlert.objects.create(
                    alert_type='data_exfiltration',
                    severity='high',
                    title=f'Possible data exfiltration by {mask_email(user.email)}',
                    description=f'{entry["access_count"]} data operations on {entry["unique_resources"]} resources',
                    user=user,
                    details={
                        'access_count': entry['access_count'],
                        'unique_resources': entry['unique_resources'],
                        'historical_avg_hourly': round(historical_avg, 2),
                        'multiplication_factor': round(entry['access_count'] / max(historical_avg, 1), 1)
                    },
                    risk_score=75.0
                )
                alerts.append(alert)
                
        except CustomUser.DoesNotExist:
            continue
    
    return alerts


def _detect_api_scanning(since_time):
    """Detect API enumeration/scanning attempts"""
    alerts = []
    
    # Look for 404s and 403s patterns
    scanning_patterns = AuditLog.objects.filter(
        action__in=['unauthorized_access', 'data_viewed'],
        severity__in=['warning', 'error'],
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        error_count=Count('id'),
        unique_paths=Count('metadata__path', distinct=True)
    ).filter(error_count__gte=50, unique_paths__gte=20)
    
    for entry in scanning_patterns:
        if not entry['ip_address']:
            continue
        
        alert = SecurityAlert.objects.create(
            alert_type='suspicious_activity',
            severity='high',
            title=f'API scanning detected from {entry["ip_address"]}',
            description=f'{entry["error_count"]} failed requests to {entry["unique_paths"]} different endpoints',
            ip_address=entry['ip_address'],
            details={
                'error_count': entry['error_count'],
                'unique_paths': entry['unique_paths'],
                'attack_pattern': 'api_enumeration'
            },
            risk_score=70.0
        )
        alerts.append(alert)
        
        # Auto-blacklist scanners
        if entry['error_count'] >= 100:
            IPBlacklist.objects.get_or_create(
                ip_address=entry['ip_address'],
                defaults={
                    'reason': 'vulnerability_scan',
                    'description': f'Auto-blocked: API scanning with {entry["error_count"]} attempts',
                    'expires_at': timezone.now() + timedelta(days=7),
                    'auto_blocked': True,
                    'threat_score': 75.0
                }
            )
    
    return alerts


def _detect_unusual_access_patterns(since_time):
    """Detect unusual data access patterns"""
    alerts = []
    
    # Night time access (assuming most users work 9-5)
    current_hour = timezone.now().hour
    if 0 <= current_hour <= 6:  # Night hours
        night_access = AuditLog.objects.filter(
            action='data_viewed',
            timestamp__gte=since_time,
            user__isnull=False
        ).values('user').annotate(
            access_count=Count('id')
        ).filter(access_count__gte=20)
        
        for entry in night_access:
            try:
                user = CustomUser.objects.get(id=entry['user'])
                
                # Check if user normally works at night
                historical_night = AuditLog.objects.filter(
                    user=user,
                    timestamp__hour__gte=0,
                    timestamp__hour__lte=6,
                    timestamp__gte=timezone.now() - timedelta(days=30)
                ).count()
                
                if historical_night < 10:  # Not a night worker
                    alert = SecurityAlert.objects.create(
                        alert_type='suspicious_activity',
                        severity='medium',
                        title=f'Unusual night access by {mask_email(user.email)}',
                        description=f'{entry["access_count"]} data accesses during night hours',
                        user=user,
                        details={
                            'access_count': entry['access_count'],
                            'time_period': 'night',
                            'local_hour': current_hour,
                            'historical_night_activity': historical_night
                        },
                        risk_score=50.0
                    )
                    alerts.append(alert)
                    
            except CustomUser.DoesNotExist:
                continue
    
    return alerts


@shared_task(bind=True, max_retries=3)
def check_system_performance(self):
    """Enhanced system performance monitoring"""
    try:
        one_hour_ago = timezone.now() - timedelta(hours=1)
        alerts_created = []
        
        # Response time analysis
        response_metrics = PerformanceMetric.objects.filter(
            metric_type='response_time',
            timestamp__gte=one_hour_ago
        ).aggregate(
            avg_time=Avg('value'),
            max_time=models.Max('value'),
            count=Count('id')
        )
        
        if response_metrics['avg_time'] and response_metrics['avg_time'] > 1000:
            alert = SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='medium',
                title='High average response time detected',
                description=f'Average response time is {response_metrics["avg_time"]:.2f}ms',
                details={
                    'avg_response_time': response_metrics['avg_time'],
                    'max_response_time': response_metrics['max_time'],
                    'request_count': response_metrics['count'],
                    'threshold': 1000,
                    'time_period': '1 hour'
                },
                risk_score=40.0
            )
            alerts_created.append(alert)
        
        # Error rate analysis
        error_metrics = self._analyze_error_rates(one_hour_ago)
        if error_metrics['alert_needed']:
            alert = SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='high',
                title='High error rate detected',
                description=f'Error rate is {error_metrics["error_rate"]:.2f}%',
                details=error_metrics,
                risk_score=65.0
            )
            alerts_created.append(alert)
        
        # Resource usage (placeholder for actual monitoring)
        self._check_resource_usage()
        
        logger.info(f"System performance check completed. Created {len(alerts_created)} alerts")
        return f"Created {len(alerts_created)} performance alerts"
        
    except Exception as e:
        logger.error(f"Error checking system performance: {str(e)}")
        self.retry(exc=e, countdown=300)


def _analyze_error_rates(since_time):
    """Analyze error rates"""
    total_requests = PerformanceMetric.objects.filter(
        metric_type='response_time',
        timestamp__gte=since_time
    ).count()
    
    error_requests = PerformanceMetric.objects.filter(
        metric_type='error_rate',
        timestamp__gte=since_time
    ).count()
    
    if total_requests > 0:
        error_rate = (error_requests / total_requests) * 100
        
        return {
            'error_rate': error_rate,
            'error_count': error_requests,
            'total_requests': total_requests,
            'threshold': 5,
            'alert_needed': error_rate > 5
        }
    
    return {'alert_needed': False}


def _check_resource_usage():
    """Check system resource usage (CPU, memory, disk)"""
    # This would integrate with system monitoring tools
    # For now, it's a placeholder
    pass


@shared_task(bind=True, max_retries=3)
def audit_session_anomalies(self):
    """Audit for session anomalies"""
    try:
        alerts_created = []
        
        # Multiple concurrent sessions
        concurrent_sessions = SessionMonitor.objects.filter(
            terminated=False,
            expires_at__gt=timezone.now()
        ).values('user').annotate(
            session_count=Count('id'),
            unique_ips=Count('ip_address', distinct=True)
        ).filter(session_count__gt=3)
        
        for entry in concurrent_sessions:
            try:
                user = CustomUser.objects.get(id=entry['user'])
                
                alert = SecurityAlert.objects.create(
                    alert_type='session_hijack',
                    severity='medium',
                    title=f'Multiple concurrent sessions for {mask_email(user.email)}',
                    description=f'{entry["session_count"]} active sessions from {entry["unique_ips"]} IPs',
                    user=user,
                    details={
                        'session_count': entry['session_count'],
                        'unique_ips': entry['unique_ips'],
                        'risk_factor': 'concurrent_sessions'
                    },
                    risk_score=55.0
                )
                alerts_created.append(alert)
                
            except CustomUser.DoesNotExist:
                continue
        
        # Long-running sessions
        long_session_threshold = timezone.now() - timedelta(hours=24)
        long_sessions = SessionMonitor.objects.filter(
            terminated=False,
            created_at__lt=long_session_threshold
        )
        
        for session in long_sessions:
            alert = SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='low',
                title=f'Long-running session detected for {mask_email(session.user.email)}',
                description=f'Session active for over 24 hours',
                user=session.user,
                ip_address=session.ip_address,
                details={
                    'session_id': str(session.id),
                    'duration_hours': (timezone.now() - session.created_at).total_seconds() / 3600,
                    'risk_factor': 'long_session'
                },
                risk_score=35.0
            )
            alerts_created.append(alert)
        
        logger.info(f"Session anomaly audit completed. Created {len(alerts_created)} alerts")
        return f"Created {len(alerts_created)} session anomaly alerts"
        
    except Exception as e:
        logger.error(f"Error auditing session anomalies: {str(e)}")
        self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def update_threat_intelligence(self):
    """Update threat intelligence from external sources"""
    try:
        updated_count = 0
        
        # Update from configured threat feeds
        threat_feeds = getattr(settings, 'THREAT_INTELLIGENCE_FEEDS', [])
        
        for feed in threat_feeds:
            try:
                if feed['type'] == 'ip_blacklist':
                    updated_count += self._update_ip_blacklist(feed)
                elif feed['type'] == 'domain_blacklist':
                    updated_count += self._update_domain_blacklist(feed)
                elif feed['type'] == 'hash_list':
                    updated_count += self._update_hash_list(feed)
            except Exception as e:
                logger.error(f"Error updating from feed {feed['name']}: {e}")
        
        # Update threat scores based on hits
        self._update_threat_scores()
        
        # Clean up expired entries
        expired = ThreatIntelligence.objects.filter(
            expires_at__lt=timezone.now()
        ).update(is_active=False)
        
        logger.info(f"Threat intelligence update completed. Updated {updated_count} entries, expired {expired}")
        return f"Updated {updated_count} threat intelligence entries"
        
    except Exception as e:
        logger.error(f"Error updating threat intelligence: {str(e)}")
        self.retry(exc=e, countdown=3600)  # Retry in 1 hour


def _update_ip_blacklist(self, feed):
    """Update IP blacklist from feed"""
    updated = 0
    
    try:
        response = requests.get(feed['url'], timeout=30)
        response.raise_for_status()
        
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse IP address (simple format assumed)
                ip = line.split()[0]
                
                threat, created = ThreatIntelligence.objects.update_or_create(
                    threat_type='ip',
                    threat_value=ip,
                    defaults={
                        'threat_level': feed.get('default_level', 'medium'),
                        'threat_category': feed.get('category', 'malware'),
                        'description': f'IP from {feed["name"]} feed',
                        'source': feed['name'],
                        'source_url': feed['url'],
                        'confidence': feed.get('confidence', 75),
                        'expires_at': timezone.now() + timedelta(days=7),
                        'is_active': True
                    }
                )
                
                if created:
                    updated += 1
                else:
                    threat.last_seen = timezone.now()
                    threat.save()
    
    except Exception as e:
        logger.error(f"Error updating IP blacklist from {feed['name']}: {e}")
    
    return updated


def _update_domain_blacklist(self, feed):
    """Update domain blacklist from feed"""
    # Similar implementation to IP blacklist
    return 0


def _update_hash_list(self, feed):
    """Update hash list from feed"""
    # Similar implementation to IP blacklist
    return 0


def _update_threat_scores(self):
    """Update threat scores based on activity"""
    # Update scores for frequently hit threats
    high_hit_threats = ThreatIntelligence.objects.filter(
        hit_count__gte=10,
        is_active=True
    )
    
    for threat in high_hit_threats:
        threat.severity_score = min(threat.severity_score * 1.1, 100.0)
        threat.save()


@shared_task(bind=True, max_retries=3)
def generate_daily_security_report(self):
    """Generate and email enhanced daily security report"""
    try:
        yesterday = timezone.now() - timedelta(days=1)
        today = timezone.now()
        
        # Comprehensive statistics
        stats = {
            'date': yesterday.date(),
            'total_logins': AuditLog.objects.filter(
                action='login',
                timestamp__date=yesterday.date()
            ).count(),
            'failed_logins': AuditLog.objects.filter(
                action='login_failed',
                timestamp__date=yesterday.date()
            ).count(),
            'unique_users': AuditLog.objects.filter(
                action='login',
                timestamp__date=yesterday.date()
            ).values('user').distinct().count(),
            'new_alerts': SecurityAlert.objects.filter(
                created_at__date=yesterday.date()
            ).count(),
            'critical_alerts': SecurityAlert.objects.filter(
                created_at__date=yesterday.date(),
                severity='critical'
            ).count(),
            'resolved_alerts': SecurityAlert.objects.filter(
                resolved_at__date=yesterday.date()
            ).count(),
            'blocked_ips': IPBlacklist.objects.filter(
                blocked_at__date=yesterday.date()
            ).count(),
            'active_users': CustomUser.objects.filter(
                last_activity__date=yesterday.date()
            ).count(),
            'new_threats': ThreatIntelligence.objects.filter(
                first_seen__date=yesterday.date()
            ).count(),
        }
        
        # Calculate trends
        prev_day = yesterday - timedelta(days=1)
        prev_stats = {
            'total_logins': AuditLog.objects.filter(
                action='login',
                timestamp__date=prev_day.date()
            ).count(),
            'failed_logins': AuditLog.objects.filter(
                action='login_failed',
                timestamp__date=prev_day.date()
            ).count(),
        }
        
        trends = {
            'login_trend': self._calculate_trend(stats['total_logins'], prev_stats['total_logins']),
            'failed_login_trend': self._calculate_trend(stats['failed_logins'], prev_stats['failed_logins']),
        }
        
        # Get top alerts
        top_alerts = SecurityAlert.objects.filter(
            created_at__date=yesterday.date()
        ).order_by('-severity', '-risk_score', '-created_at')[:10]
        
        # Get top threats
        top_threats = AuditLog.objects.filter(
            action__in=['login_failed', 'unauthorized_access'],
            timestamp__date=yesterday.date()
        ).values('ip_address').annotate(
            threat_count=Count('id')
        ).order_by('-threat_count')[:5]
        
        # Security score calculation
        security_score = self._calculate_security_score(stats)
        
        # Send to admins and security team
        recipients = list(CustomUser.objects.filter(
            Q(is_superuser=True) | Q(groups__name='security_team'),
            is_active=True
        ).values_list('email', flat=True).distinct())
        
        if recipients:
            html_content = render_to_string('emails/daily_security_report.html', {
                'stats': stats,
                'trends': trends,
                'top_alerts': top_alerts,
                'top_threats': top_threats,
                'security_score': security_score,
                'report_date': yesterday.date(),
            })
            
            email = EmailMessage(
                subject=f'Daily Security Report - {yesterday.date()} - Score: {security_score}/100',
                body=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=recipients,
            )
            email.content_subtype = 'html'
            
            # Attach CSV summary
            csv_content = self._generate_report_csv(stats, top_alerts, top_threats)
            email.attach(
                f'security_summary_{yesterday.date()}.csv',
                csv_content,
                'text/csv'
            )
            
            email.send()
            
            logger.info(f"Daily security report sent to {len(recipients)} recipients")
        
        return f"Report sent to {len(recipients)} recipients"
        
    except Exception as e:
        logger.error(f"Error generating daily security report: {str(e)}")
        self.retry(exc=e, countdown=3600)


def _calculate_trend(self, current, previous):
    """Calculate percentage trend"""
    if previous == 0:
        return 100 if current > 0 else 0
    return round(((current - previous) / previous) * 100, 1)


def _calculate_security_score(self, stats):
    """Calculate overall security score (0-100)"""
    score = 100
    
    # Deduct for failed logins
    if stats['total_logins'] > 0:
        failed_ratio = stats['failed_logins'] / stats['total_logins']
        score -= min(failed_ratio * 50, 25)  # Max 25 point deduction
    
    # Deduct for critical alerts
    score -= min(stats['critical_alerts'] * 5, 20)  # Max 20 point deduction
    
    # Deduct for unresolved alerts
    unresolved = stats['new_alerts'] - stats['resolved_alerts']
    score -= min(unresolved * 2, 15)  # Max 15 point deduction
    
    # Deduct for blocked IPs (indicates attacks)
    score -= min(stats['blocked_ips'] * 2, 10)  # Max 10 point deduction
    
    return max(0, round(score))


def _generate_report_csv(self, stats, alerts, threats):
    """Generate CSV content for report"""
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Daily Security Report', stats['date']])
    writer.writerow([])
    
    # Summary stats
    writer.writerow(['Metric', 'Value'])
    for key, value in stats.items():
        if key != 'date':
            writer.writerow([key.replace('_', ' ').title(), value])
    
    writer.writerow([])
    
    # Top alerts
    writer.writerow(['Top Security Alerts'])
    writer.writerow(['Severity', 'Type', 'Title', 'Risk Score'])
    for alert in alerts[:5]:
        writer.writerow([
            alert.get_severity_display(),
            alert.get_alert_type_display(),
            alert.title[:50],
            alert.risk_score
        ])
    
    writer.writerow([])
    
    # Top threats
    writer.writerow(['Top Threat IPs'])
    writer.writerow(['IP Address', 'Threat Count'])
    for threat in threats:
        writer.writerow([threat['ip_address'], threat['threat_count']])
    
    return output.getvalue()


@shared_task(bind=True, max_retries=3)
def system_health_check(self):
    """Enhanced system health checks with monitoring"""
    try:
        health_status = {
            'timestamp': timezone.now().isoformat(),
            'checks': {},
            'overall_status': 'healthy'
        }
        
        # Database connectivity
        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            health_status['checks']['database'] = 'ok'
        except Exception as e:
            health_status['checks']['database'] = 'error'
            health_status['overall_status'] = 'critical'
            logger.error(f"Database health check failed: {e}")
        
        # Cache connectivity
        try:
            from django.core.cache import cache
            cache.set('health_check', 'ok', 30)
            if cache.get('health_check') == 'ok':
                health_status['checks']['cache'] = 'ok'
            else:
                raise Exception("Cache read/write failed")
        except Exception as e:
            health_status['checks']['cache'] = 'error'
            health_status['overall_status'] = 'degraded'
            logger.error(f"Cache health check failed: {e}")
        
        # Check disk space
        try:
            import shutil
            usage = shutil.disk_usage('/')
            percent_used = (usage.used / usage.total) * 100
            
            if percent_used > 90:
                health_status['checks']['disk_space'] = 'critical'
                health_status['overall_status'] = 'degraded'
                
                SecurityAlert.objects.create(
                    alert_type='suspicious_activity',
                    severity='high',
                    title='Low disk space',
                    description=f'Disk usage at {percent_used:.1f}%',
                    details={'percent_used': percent_used}
                )
            else:
                health_status['checks']['disk_space'] = 'ok'
        except Exception as e:
            health_status['checks']['disk_space'] = 'unknown'
            logger.error(f"Disk space check failed: {e}")
        
        # Check memory usage
        try:
            import psutil
            memory = psutil.virtual_memory()
            
            if memory.percent > 85:
                health_status['checks']['memory'] = 'warning'
                if memory.percent > 95:
                    health_status['overall_status'] = 'degraded'
            else:
                health_status['checks']['memory'] = 'ok'
        except ImportError:
            health_status['checks']['memory'] = 'unknown'
        
        # Record metrics
        PerformanceMetric.objects.create(
            metric_type='health_check',
            value=1 if health_status['overall_status'] == 'healthy' else 0,
            unit='status',
            metadata=health_status
        )
        
        # Create alert if unhealthy
        if health_status['overall_status'] != 'healthy':
            SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='critical' if health_status['overall_status'] == 'critical' else 'high',
                title='System health check failed',
                description=f'System status: {health_status["overall_status"]}',
                details=health_status
            )
        
        logger.info(f"Health check completed: {health_status['overall_status']}")
        return health_status
        
    except Exception as e:
        logger.error(f"System health check failed: {str(e)}")
        
        # Create critical alert
        SecurityAlert.objects.create(
            alert_type='suspicious_activity',
            severity='critical',
            title='System health check failed',
            description=str(e),
            details={'error': str(e)}
        )
        
        self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def cleanup_expired_blacklist(self):
    """Enhanced cleanup of expired IP blacklist entries"""
    try:
        # Find expired entries
        expired = IPBlacklist.objects.filter(
            expires_at__lt=timezone.now(),
            is_active=True
        )
        
        expired_count = expired.count()
        
        # Log before cleanup
        for entry in expired[:100]:  # Log first 100
            log_security_event(
                event_type='ip_unblocked',
                severity='info',
                message=f'Auto-unblocking expired IP: {entry.ip_address}',
                ip_address=entry.ip_address,
                metadata={'reason': 'expired', 'blocked_duration_hours': 
                         (entry.expires_at - entry.blocked_at).total_seconds() / 3600}
            )
        
        # Batch update
        with transaction.atomic():
            expired.update(
                is_active=False,
                unblocked_at=timezone.now()
            )
        
        # Clean up old inactive entries (> 90 days)
        old_date = timezone.now() - timedelta(days=90)
        old_deleted = IPBlacklist.objects.filter(
            is_active=False,
            unblocked_at__lt=old_date
        ).delete()[0]
        
        logger.info(f"Cleaned up {expired_count} expired and {old_deleted} old blacklist entries")
        return f"Cleaned up {expired_count} expired and {old_deleted} old entries"
        
    except Exception as e:
        logger.error(f"Error cleaning up blacklist: {str(e)}")
        self.retry(exc=e, countdown=3600)


@shared_task(bind=True, max_retries=3)
def cleanup_old_alerts(self):
    """Clean up old alerts based on retention policy"""
    try:
        config = SecurityConfiguration.get_active_config()
        retention_date = timezone.now() - timedelta(days=config.audit_retention_days)
        
        # Archive critical alerts before deletion
        critical_alerts = SecurityAlert.objects.filter(
            created_at__lt=retention_date,
            severity='critical'
        )
        
        if critical_alerts.exists():
            # Archive to separate storage (placeholder)
            archived_count = self._archive_alerts(critical_alerts)
            logger.info(f"Archived {archived_count} critical alerts")
        
        # Delete old non-critical alerts
        deleted_count = SecurityAlert.objects.filter(
            created_at__lt=retention_date,
            severity__in=['low', 'info']
        ).delete()[0]
        
        # Delete old resolved alerts
        resolved_deleted = SecurityAlert.objects.filter(
            resolved_at__lt=retention_date,
            status='resolved'
        ).delete()[0]
        
        total_deleted = deleted_count + resolved_deleted
        
        logger.info(f"Cleaned up {total_deleted} old alerts")
        
        # Log cleanup
        log_security_event(
            event_type='data_deleted',
            severity='info',
            message=f'Cleaned up {total_deleted} old security alerts',
            metadata={
                'retention_days': config.audit_retention_days,
                'deleted_count': total_deleted
            }
        )
        
        return f"Cleaned up {total_deleted} old alerts"
        
    except Exception as e:
        logger.error(f"Error cleaning up alerts: {str(e)}")
        self.retry(exc=e, countdown=3600)


def _archive_alerts(self, alerts):
    """Archive alerts to long-term storage"""
    # This would integrate with your archive storage solution
    # For now, just mark them
    archived = 0
    
    for alert in alerts:
        # Create archive record (placeholder)
        # archive_storage.store(alert)
        archived += 1
    
    return archived


@shared_task(bind=True, max_retries=3)
def generate_security_report_task(self, report_type, period_days, user_id):
    """Enhanced security report generation with better error handling"""
    try:
        from accounts.models import CustomUser
        from django.core.mail import EmailMessage
        from django.template.loader import render_to_string
        import csv
        from io import StringIO
        import os
        import tempfile
        
        # Get user
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            logger.error(f"User {user_id} not found for report generation")
            return "User not found"
        
        # Calculate date range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=period_days)
        
        # Create report object
        report = SecurityReport.objects.create(
            title=f'{report_type.title()} Security Report',
            report_type=report_type,
            status='generating',
            date_range_start=start_date,
            date_range_end=end_date,
            requested_by=user,
            file_format='csv'
        )
        
        try:
            # Generate report data based on type
            if report_type == 'summary':
                report_data = self._generate_summary_report_data(start_date, end_date)
            elif report_type == 'threats':
                report_data = self._generate_threat_report_data(start_date, end_date)
            elif report_type == 'compliance':
                report_data = self._generate_compliance_report_data(start_date, end_date)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
            
            # Generate CSV file
            csv_content = self._generate_report_csv_content(report_type, report_data, start_date, end_date)
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
                tmp_file.write(csv_content)
                tmp_file_path = tmp_file.name
            
            # Save file to report
            with open(tmp_file_path, 'rb') as f:
                report.file.save(
                    f'security_report_{report_type}_{end_date.date()}.csv',
                    f
                )
            
            # Update report status
            report.mark_completed(
                summary_data={
                    'record_count': report_data.get('total_records', 0),
                    'generation_time': (timezone.now() - report.created_at).total_seconds()
                }
            )
            
            # Clean up temp file
            os.unlink(tmp_file_path)
            
            # Send email notification
            self._send_report_email(user, report, report_data)
            
            logger.info(f"Security report generated successfully: {report.id}")
            return f"Report generated: {report.id}"
            
        except Exception as e:
            logger.error(f"Error generating report content: {e}")
            report.mark_failed(str(e))
            raise
            
    except Exception as e:
        logger.error(f"Error in report generation task: {str(e)}")
        self.retry(exc=e, countdown=300)


def _generate_summary_report_data(self, start_date, end_date):
    """Generate summary report data"""
    data = {
        'alerts': {
            'total': SecurityAlert.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'by_severity': dict(
                SecurityAlert.objects.filter(
                    created_at__range=[start_date, end_date]
                ).values_list('severity').annotate(count=Count('id'))
            ),
            'by_type': dict(
                SecurityAlert.objects.filter(
                    created_at__range=[start_date, end_date]
                ).values_list('alert_type').annotate(count=Count('id'))[:20]
            ),
            'resolved': SecurityAlert.objects.filter(
                resolved_at__range=[start_date, end_date]
            ).count(),
            'avg_resolution_time': SecurityAlert.objects.filter(
                resolved_at__range=[start_date, end_date],
                acknowledged_at__isnull=False
            ).annotate(
                resolution_time=F('resolved_at') - F('acknowledged_at')
            ).aggregate(
                avg_time=Avg('resolution_time')
            )['avg_time'],
        },
        'authentication': {
            'total_logins': AuditLog.objects.filter(
                action='login',
                timestamp__range=[start_date, end_date]
            ).count(),
            'failed_logins': AuditLog.objects.filter(
                action='login_failed',
                timestamp__range=[start_date, end_date]
            ).count(),
            'unique_users': AuditLog.objects.filter(
                action='login',
                timestamp__range=[start_date, end_date]
            ).values('user').distinct().count(),
            'mfa_failures': AuditLog.objects.filter(
                action='mfa_failed',
                timestamp__range=[start_date, end_date]
            ).count(),
        },
        'threats': {
            'blocked_ips': IPBlacklist.objects.filter(
                blocked_at__range=[start_date, end_date]
            ).count(),
            'active_blacklist': IPBlacklist.objects.filter(
                is_active=True
            ).count(),
            'threat_intel_hits': ThreatIntelligence.objects.filter(
                last_seen__range=[start_date, end_date]
            ).aggregate(
                total_hits=models.Sum('hit_count')
            )['total_hits'] or 0,
        },
        'sessions': {
            'total_sessions': SessionMonitor.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'suspicious_sessions': SessionMonitor.objects.filter(
                created_at__range=[start_date, end_date],
                is_suspicious=True
            ).count(),
            'terminated_sessions': SessionMonitor.objects.filter(
                terminated_at__range=[start_date, end_date]
            ).count(),
        },
        'total_records': 0
    }
    
    # Calculate total records
    data['total_records'] = sum([
        data['alerts']['total'],
        data['authentication']['total_logins'],
        data['threats']['blocked_ips'],
        data['sessions']['total_sessions']
    ])
    
    return data


def _generate_threat_report_data(self, start_date, end_date):
    """Generate detailed threat report data"""
    # Top threat IPs
    top_threat_ips = list(
        AuditLog.objects.filter(
            action__in=['login_failed', 'unauthorized_access'],
            timestamp__range=[start_date, end_date]
        ).values('ip_address').annotate(
            attempts=Count('id'),
            unique_users=Count('user', distinct=True),
            first_seen=models.Min('timestamp'),
            last_seen=models.Max('timestamp')
        ).order_by('-attempts')[:50]
    )
    
    # Alert type distribution
    alert_types = list(
        SecurityAlert.objects.filter(
            created_at__range=[start_date, end_date]
        ).values('alert_type').annotate(
            count=Count('id'),
            avg_risk=Avg('risk_score')
        ).order_by('-count')
    )
    
    # Threat timeline
    threat_timeline = []
    current_date = start_date.date()
    while current_date <= end_date.date():
        threat_timeline.append({
            'date': current_date.isoformat(),
            'alerts': SecurityAlert.objects.filter(
                created_at__date=current_date
            ).count(),
            'failed_logins': AuditLog.objects.filter(
                action='login_failed',
                timestamp__date=current_date
            ).count(),
            'blocked_ips': IPBlacklist.objects.filter(
                blocked_at__date=current_date
            ).count(),
        })
        current_date += timedelta(days=1)
    
    # Active threats
    active_threats = list(
        ThreatIntelligence.objects.filter(
            is_active=True,
            last_seen__range=[start_date, end_date]
        ).order_by('-severity_score', '-hit_count')[:50]
    )
    
    return {
        'top_threat_ips': top_threat_ips,
        'alert_types': alert_types,
        'threat_timeline': threat_timeline,
        'active_threats': active_threats,
        'total_records': len(top_threat_ips) + len(alert_types) + len(active_threats)
    }


def _generate_compliance_report_data(self, start_date, end_date):
    """Generate compliance report data"""
    from audit_trail.models import ComplianceLog
    
    # User compliance
    total_users = CustomUser.objects.filter(is_active=True).count()
    mfa_compliant = CustomUser.objects.filter(
        is_active=True,
        mfa_enabled=True
    ).count()
    
    # Password compliance
    config = SecurityConfiguration.get_active_config()
    password_expired = CustomUser.objects.filter(
        is_active=True,
        last_password_change__lt=timezone.now() - timedelta(days=config.password_expiry_days)
    ).count()
    
    # Audit compliance
    audit_coverage = {
        'total_actions': AuditLog.objects.filter(
            timestamp__range=[start_date, end_date]
        ).count(),
        'high_risk_actions': AuditLog.objects.filter(
            timestamp__range=[start_date, end_date],
            severity__in=['high', 'critical']
        ).count(),
        'data_access_logs': DataAccessLog.objects.filter(
            timestamp__range=[start_date, end_date]
        ).count() if hasattr(DataAccessLog, 'objects') else 0,
    }
    
    # Compliance frameworks
    from .models import ComplianceFramework
    frameworks = list(
        ComplianceFramework.objects.filter(
            is_active=True
        ).values(
            'name', 'framework_type', 'compliance_percentage',
            'controls_total', 'controls_implemented'
        )
    )
    
    # Security controls
    security_controls = {
        'mfa_enabled': config.mfa_required,
        'session_timeout': config.session_timeout_minutes,
        'password_complexity': all([
            config.require_uppercase,
            config.require_lowercase,
            config.require_numbers,
            config.require_special_chars
        ]),
        'ip_whitelist': config.ip_whitelist_enabled,
        'rate_limiting': config.rate_limit_enabled,
        'audit_retention': config.audit_retention_days,
    }
    
    return {
        'user_compliance': {
            'total_users': total_users,
            'mfa_compliant': mfa_compliant,
            'mfa_compliance_rate': (mfa_compliant / total_users * 100) if total_users > 0 else 0,
            'password_expired': password_expired,
            'password_compliance_rate': ((total_users - password_expired) / total_users * 100) if total_users > 0 else 0,
        },
        'audit_coverage': audit_coverage,
        'frameworks': frameworks,
        'security_controls': security_controls,
        'total_records': total_users + len(frameworks)
    }


def _generate_report_csv_content(self, report_type, data, start_date, end_date):
    """Generate CSV content for the report"""
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow([f'{report_type.title()} Security Report'])
    writer.writerow([f'Period: {start_date.date()} to {end_date.date()}'])
    writer.writerow(['Generated:', timezone.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])
    
    if report_type == 'summary':
        # Summary statistics
        writer.writerow(['Security Summary'])
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Total Alerts', data['alerts']['total']])
        writer.writerow(['Resolved Alerts', data['alerts']['resolved']])
        writer.writerow(['Total Logins', data['authentication']['total_logins']])
        writer.writerow(['Failed Logins', data['authentication']['failed_logins']])
        writer.writerow(['Blocked IPs', data['threats']['blocked_ips']])
        writer.writerow(['Suspicious Sessions', data['sessions']['suspicious_sessions']])
        
        writer.writerow([])
        writer.writerow(['Alerts by Severity'])
        for severity, count in data['alerts']['by_severity'].items():
            writer.writerow([severity, count])
            
    elif report_type == 'threats':
        # Top threat IPs
        writer.writerow(['Top Threat IPs'])
        writer.writerow(['IP Address', 'Attempts', 'Unique Users', 'First Seen', 'Last Seen'])
        for threat in data['top_threat_ips'][:20]:
            writer.writerow([
                threat['ip_address'],
                threat['attempts'],
                threat['unique_users'],
                threat['first_seen'].strftime('%Y-%m-%d %H:%M') if threat['first_seen'] else '',
                threat['last_seen'].strftime('%Y-%m-%d %H:%M') if threat['last_seen'] else ''
            ])
        
        writer.writerow([])
        writer.writerow(['Alert Type Distribution'])
        writer.writerow(['Type', 'Count', 'Avg Risk Score'])
        for alert_type in data['alert_types']:
            writer.writerow([
                alert_type['alert_type'],
                alert_type['count'],
                round(alert_type['avg_risk'] or 0, 2)
            ])
            
    elif report_type == 'compliance':
        # User compliance
        writer.writerow(['User Compliance'])
        writer.writerow(['Metric', 'Value', 'Rate'])
        writer.writerow([
            'MFA Compliance',
            f"{data['user_compliance']['mfa_compliant']}/{data['user_compliance']['total_users']}",
            f"{data['user_compliance']['mfa_compliance_rate']:.1f}%"
        ])
        writer.writerow([
            'Password Compliance',
            f"{data['user_compliance']['total_users'] - data['user_compliance']['password_expired']}/{data['user_compliance']['total_users']}",
            f"{data['user_compliance']['password_compliance_rate']:.1f}%"
        ])
        
        writer.writerow([])
        writer.writerow(['Security Controls'])
        writer.writerow(['Control', 'Status'])
        for control, status in data['security_controls'].items():
            writer.writerow([control.replace('_', ' ').title(), 'Enabled' if status else 'Disabled'])
    
    return output.getvalue()


def _send_report_email(self, user, report, data):
    """Send report email to user"""
    try:
        # Create HTML email
        html_content = render_to_string('emails/security_report_ready.html', {
            'user': user,
            'report': report,
            'data': data,
            'download_url': f"{settings.SITE_URL}/api/security/reports/{report.id}/download/"
        })
        
        # Send email
        email = EmailMessage(
            subject=f'Security Report Ready - {report.get_report_type_display()}',
            body=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.content_subtype = 'html'
        email.send()
        
        logger.info(f"Report email sent to {mask_email(user.email)}")
        
    except Exception as e:
        logger.error(f"Error sending report email: {e}")