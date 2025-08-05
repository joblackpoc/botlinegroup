
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from datetime import timedelta
import logging
from .models import CustomUser
from security_suite.models import SecurityAlert
from audit_trail.models import AuditLog
from django.db.models import Q

logger = logging.getLogger(__name__)


@shared_task
def check_password_expiry():
    """Check for users with expiring passwords and send notifications"""
    try:
        config = settings.PASSWORD_EXPIRY_DAYS
        warning_days = 7
        
        # Calculate dates
        expiry_warning_date = timezone.now() + timedelta(days=warning_days)
        
        # Find users whose passwords will expire soon
        users_to_notify = CustomUser.objects.filter(
            is_active=True,
            last_password_change__lte=expiry_warning_date - timedelta(days=config)
        ).exclude(
            last_password_change__lte=timezone.now() - timedelta(days=config)
        )
        
        notified_count = 0
        
        for user in users_to_notify:
            days_until_expiry = (
                user.last_password_change + timedelta(days=config) - timezone.now()
            ).days
            
            # Send email notification
            send_password_expiry_notification.delay(user.id, days_until_expiry)
            notified_count += 1
        
        # Find users with already expired passwords
        expired_users = CustomUser.objects.filter(
            is_active=True,
            last_password_change__lte=timezone.now() - timedelta(days=config)
        )
        
        for user in expired_users:
            # Create security alert
            SecurityAlert.objects.get_or_create(
                alert_type='expired_password',
                user=user,
                status='new',
                defaults={
                    'severity': 'high',
                    'title': f'Password expired for user {user.email}',
                    'description': 'User password has expired and needs to be reset',
                    'details': {
                        'user_email': user.email,
                        'last_change': user.last_password_change.isoformat(),
                        'expiry_days': config
                    }
                }
            )
        
        logger.info(f"Password expiry check completed. Notified {notified_count} users")
        return f"Notified {notified_count} users about password expiry"
        
    except Exception as e:
        logger.error(f"Error checking password expiry: {str(e)}")
        raise


@shared_task
def send_password_expiry_notification(user_id, days_until_expiry):
    """Send password expiry notification email"""
    try:
        user = CustomUser.objects.get(id=user_id)
        
        context = {
            'user': user,
            'days_until_expiry': days_until_expiry,
            'change_password_url': settings.FRONTEND_URL + '/account/password/change/'
        }
        
        html_content = render_to_string('emails/password_expiry_warning.html', context)
        
        send_mail(
            subject=f'Password Expiring in {days_until_expiry} Days',
            message=f'Your password will expire in {days_until_expiry} days. Please change it soon.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_content,
            fail_silently=False,
        )
        
        # Log the notification
        AuditLog.log(
            action='data_viewed',
            user=user,
            severity='info',
            message=f'Password expiry notification sent to {user.email}',
            metadata={
                'days_until_expiry': days_until_expiry,
                'notification_type': 'password_expiry'
            }
        )
        
        return f"Password expiry notification sent to {user.email}"
        
    except CustomUser.DoesNotExist:
        logger.error(f"User {user_id} not found")
        raise
    except Exception as e:
        logger.error(f"Error sending password expiry notification: {str(e)}")
        raise


@shared_task
def send_approval_notification(user_id, approved_by_id, status):
    """Send notification when user is approved/rejected"""
    try:
        user = CustomUser.objects.get(id=user_id)
        approved_by = CustomUser.objects.get(id=approved_by_id)
        
        context = {
            'user': user,
            'approved_by': approved_by,
            'status': status,
            'login_url': settings.FRONTEND_URL + '/login/'
        }
        
        if status == 'approved':
            subject = 'Your account has been approved'
            template = 'emails/account_approved.html'
        else:
            subject = 'Your account registration status'
            template = 'emails/account_rejected.html'
        
        html_content = render_to_string(template, context)
        
        send_mail(
            subject=subject,
            message=f'Your account registration has been {status}.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_content,
            fail_silently=False,
        )
        
        return f"Approval notification sent to {user.email}"
        
    except CustomUser.DoesNotExist:
        logger.error(f"User not found")
        raise
    except Exception as e:
        logger.error(f"Error sending approval notification: {str(e)}")
        raise


@shared_task
def send_mfa_setup_reminder(user_id):
    """Send reminder to set up MFA"""
    try:
        user = CustomUser.objects.get(id=user_id)
        
        if user.mfa_enabled:
            return "User already has MFA enabled"
        
        context = {
            'user': user,
            'setup_url': settings.FRONTEND_URL + '/account/mfa/setup/'
        }
        
        html_content = render_to_string('emails/mfa_setup_reminder.html', context)
        
        send_mail(
            subject='Security Alert: Please enable Two-Factor Authentication',
            message='Please enable two-factor authentication for your account.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_content,
            fail_silently=False,
        )
        
        # Log the reminder
        AuditLog.log(
            action='data_viewed',
            user=user,
            severity='info',
            message=f'MFA setup reminder sent to {user.email}',
            metadata={'notification_type': 'mfa_reminder'}
        )
        
        return f"MFA setup reminder sent to {user.email}"
        
    except CustomUser.DoesNotExist:
        logger.error(f"User {user_id} not found")
        raise
    except Exception as e:
        logger.error(f"Error sending MFA setup reminder: {str(e)}")
        raise


@shared_task
def cleanup_inactive_users():
    """Clean up users who never completed registration"""
    try:
        # Find users who registered but never logged in after 30 days
        cutoff_date = timezone.now() - timedelta(days=30)
        
        inactive_users = CustomUser.objects.filter(
            date_joined__lt=cutoff_date,
            last_login__isnull=True,
            is_active=True,
            approval_status='pending'
        )
        
        count = inactive_users.count()
        
        # Deactivate these users
        inactive_users.update(
            is_active=False,
            approval_status='rejected'
        )
        
        # Log the cleanup
        AuditLog.log(
            action='user_deleted',
            severity='info',
            message=f'Cleaned up {count} inactive user registrations',
            metadata={
                'count': count,
                'cutoff_days': 30
            }
        )
        
        logger.info(f"Cleaned up {count} inactive users")
        return f"Cleaned up {count} inactive users"
        
    except Exception as e:
        logger.error(f"Error cleaning up inactive users: {str(e)}")
        raise


@shared_task
def send_new_user_notification_to_admins(user_id):
    """Notify admins about new user registration"""
    try:
        user = CustomUser.objects.get(id=user_id)
        
        # Get all admins
        admins = CustomUser.objects.filter(
            Q(is_superuser=True) | Q(user_type='admin'),
            is_active=True
        )
        
        context = {
            'user': user,
            'approval_url': settings.FRONTEND_URL + '/dashboard/users/approval-queue/'
        }
        
        html_content = render_to_string('emails/new_user_notification.html', context)
        
        for admin in admins:
            send_mail(
                subject=f'New User Registration: {user.email}',
                message=f'A new user {user.email} has registered and is awaiting approval.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[admin.email],
                html_message=html_content,
                fail_silently=False,
            )
        
        return f"New user notification sent to {admins.count()} admins"
        
    except CustomUser.DoesNotExist:
        logger.error(f"User {user_id} not found")
        raise
    except Exception as e:
        logger.error(f"Error sending new user notification: {str(e)}")
        raise


@shared_task
def enforce_mfa_for_users():
    """Enforce MFA for users who haven't set it up after grace period"""
    try:
        grace_period_days = settings.MFA_GRACE_PERIOD_DAYS
        cutoff_date = timezone.now() - timedelta(days=grace_period_days)
        
        # Find users who need MFA enforcement
        users_to_enforce = CustomUser.objects.filter(
            is_active=True,
            mfa_enabled=False,
            first_login__lt=cutoff_date,
            is_superuser=False
        ).exclude(
            mfa_enforced_at__isnull=False
        )
        
        count = users_to_enforce.count()
        
        # Mark MFA as enforced
        users_to_enforce.update(mfa_enforced_at=timezone.now())
        
        # Send notifications
        for user in users_to_enforce:
            send_mfa_enforcement_notification.delay(user.id)
        
        # Create security alerts
        for user in users_to_enforce:
            SecurityAlert.objects.create(
                alert_type='mfa_bypass',
                severity='high',
                title=f'MFA enforcement activated for {user.email}',
                description='User must set up MFA on next login',
                user=user,
                details={
                    'grace_period_days': grace_period_days,
                    'first_login': user.first_login.isoformat() if user.first_login else None
                }
            )
        
        logger.info(f"MFA enforced for {count} users")
        return f"MFA enforced for {count} users"
        
    except Exception as e:
        logger.error(f"Error enforcing MFA: {str(e)}")
        raise


@shared_task
def send_mfa_enforcement_notification(user_id):
    """Send notification about MFA enforcement"""
    try:
        user = CustomUser.objects.get(id=user_id)
        
        context = {
            'user': user,
            'setup_url': settings.FRONTEND_URL + '/account/mfa/setup/'
        }
        
        html_content = render_to_string('emails/mfa_enforcement.html', context)
        
        send_mail(
            subject='Action Required: Two-Factor Authentication is Now Mandatory',
            message='Two-factor authentication is now required for your account. You must set it up on your next login.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_content,
            fail_silently=False,
        )
        
        return f"MFA enforcement notification sent to {user.email}"
        
    except CustomUser.DoesNotExist:
        logger.error(f"User {user_id} not found")
        raise
    except Exception as e:
        logger.error(f"Error sending MFA enforcement notification: {str(e)}")
        raise


@shared_task
def sync_line_user_info(user_id):
    """Sync user information from LINE"""
    try:
        from line_bot.utils import get_line_user_profile
        
        user = CustomUser.objects.get(id=user_id)
        
        if not user.line_user_id:
            return "User has no LINE user ID"
        
        # Get profile from LINE
        profile = get_line_user_profile(user.line_user_id)
        
        if profile:
            # Update user information
            user.line_display_name = profile.get('displayName', '')
            user.save()
            
            # Log the sync
            AuditLog.log(
                action='user_updated',
                user=user,
                severity='info',
                message=f'LINE profile synced for {user.email}',
                metadata={
                    'line_user_id': user.line_user_id,
                    'display_name': user.line_display_name
                }
            )
            
            return f"LINE profile synced for {user.email}"
        else:
            return "Failed to get LINE profile"
        
    except CustomUser.DoesNotExist:
        logger.error(f"User {user_id} not found")
        raise
    except Exception as e:
        logger.error(f"Error syncing LINE user info: {str(e)}")
        raise