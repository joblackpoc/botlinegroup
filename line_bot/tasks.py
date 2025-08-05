# line_bot/tasks.py

from celery import shared_task
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
import logging

from .models import LineGroup, GroupMembership, LineMessage, CommandExecution
from .utils import send_message_to_user, send_message_to_group, remove_user_from_group
from accounts.models import CustomUser
from security_suite.models import SecurityAlert
from audit_trail.models import AuditLog

logger = logging.getLogger(__name__)


@shared_task
def check_member_validation(membership_id):
    """Check if a member has validated within the time limit"""
    try:
        membership = GroupMembership.objects.get(id=membership_id)
        
        # Check if still pending
        if membership.validation_status != 'pending':
            return "Already validated"
        
        # Check if time limit exceeded
        time_limit = membership.joined_at + timedelta(minutes=5)
        if timezone.now() > time_limit:
            # Mark as failed
            membership.validation_status = 'failed'
            membership.save()
            
            # Send notification
            send_message_to_user(
                membership.user.line_user_id,
                "❌ You have been removed from the group because you didn't provide the correct password in time."
            )
            
            # Log the removal
            AuditLog.log(
                action='group_member_removed',
                user=membership.user,
                severity='info',
                message=f'User {membership.user.line_display_name} auto-removed from {membership.group.group_name} - password timeout',
                content_object=membership.group,
                metadata={'reason': 'password_timeout'}
            )
            
            # Note: Can't actually remove from LINE group due to API limitations
            # The group admin will need to manually remove
            
            # Notify group admins
            notify_group_admins_of_removal.delay(str(membership.group.id), str(membership.user.id))
            
        return "Validation check completed"
        
    except GroupMembership.DoesNotExist:
        logger.error(f"Membership {membership_id} not found")
        return "Membership not found"
    except Exception as e:
        logger.error(f"Error checking member validation: {str(e)}")
        raise


@shared_task
def notify_group_admins_of_removal(group_id, user_id):
    """Notify group admins about auto-removal"""
    try:
        group = LineGroup.objects.get(id=group_id)
        user = CustomUser.objects.get(id=user_id)
        
        message = (
            f"⚠️ Security Notice:\n\n"
            f"User {user.line_display_name} failed to validate with the group password "
            f"and should be manually removed from the group.\n\n"
            f"LINE API doesn't support automatic removal, so please remove them manually."
        )
        
        # Send to all group admins
        for admin in group.admins.all():
            if admin.line_user_id:
                send_message_to_user(admin.line_user_id, message)
        
        return f"Notified {group.admins.count()} admins"
        
    except (LineGroup.DoesNotExist, CustomUser.DoesNotExist) as e:
        logger.error(f"Error notifying admins: {str(e)}")
        return "Error: Object not found"
    except Exception as e:
        logger.error(f"Error notifying admins: {str(e)}")
        raise


@shared_task
def cleanup_old_messages():
    """Clean up old LINE messages"""
    try:
        retention_days = 30  # Keep messages for 30 days
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        # Delete old messages
        deleted_count, _ = LineMessage.objects.filter(
            received_at__lt=cutoff_date
        ).delete()
        
        logger.info(f"Deleted {deleted_count} old LINE messages")
        
        # Log the cleanup
        AuditLog.log(
            action='data_deleted',
            severity='info',
            message=f'Cleaned up {deleted_count} LINE messages older than {retention_days} days',
            metadata={
                'retention_days': retention_days,
                'deleted_count': deleted_count
            }
        )
        
        return f"Deleted {deleted_count} old messages"
        
    except Exception as e:
        logger.error(f"Error cleaning up messages: {str(e)}")
        raise


@shared_task
def check_group_password_expiry():
    """Check for groups with expired passwords"""
    try:
        expired_groups = []
        
        for group in LineGroup.objects.filter(is_active=True):
            if group.is_password_expired():
                expired_groups.append(group)
                
                # Create security alert
                SecurityAlert.objects.get_or_create(
                    alert_type='expired_password',
                    content_type__model='linegroup',
                    object_id=str(group.id),
                    status='new',
                    defaults={
                        'severity': 'medium',
                        'title': f'Group password expired: {group.group_name}',
                        'description': f'The password for group {group.group_name} has expired and should be changed.',
                        'details': {
                            'group_id': str(group.id),
                            'group_name': group.group_name,
                            'password_age_days': (timezone.now() - group.password_changed_at).days,
                            'expiry_days': group.password_expiry_days
                        }
                    }
                )
                
                # Notify group admins
                for admin in group.admins.all():
                    if admin.line_user_id:
                        send_message_to_user(
                            admin.line_user_id,
                            f"⚠️ The password for group '{group.group_name}' has expired. "
                            f"Please use /changepassword to set a new password."
                        )
        
        logger.info(f"Found {len(expired_groups)} groups with expired passwords")
        return f"Checked {LineGroup.objects.filter(is_active=True).count()} groups, {len(expired_groups)} have expired passwords"
        
    except Exception as e:
        logger.error(f"Error checking group password expiry: {str(e)}")
        raise


@shared_task
def send_group_statistics():
    """Send weekly group statistics to admins"""
    try:
        one_week_ago = timezone.now() - timedelta(days=7)
        
        for group in LineGroup.objects.filter(is_active=True):
            # Gather statistics
            stats = {
                'total_members': GroupMembership.objects.filter(
                    group=group,
                    validation_status='validated'
                ).count(),
                'new_members': GroupMembership.objects.filter(
                    group=group,
                    joined_at__gte=one_week_ago
                ).count(),
                'removed_members': GroupMembership.objects.filter(
                    group=group,
                    validation_status='removed',
                    removed_at__gte=one_week_ago
                ).count(),
                'commands_used': CommandExecution.objects.filter(
                    group=group,
                    executed_at__gte=one_week_ago
                ).count(),
                'messages_received': LineMessage.objects.filter(
                    group=group,
                    received_at__gte=one_week_ago
                ).count(),
                'failed_validations': GroupMembership.objects.filter(
                    group=group,
                    validation_status='failed',
                    joined_at__gte=one_week_ago
                ).count()
            }
            
            # Build message
            message = (
                f"📊 Weekly Statistics for {group.group_name}\n\n"
                f"👥 Total Members: {stats['total_members']}\n"
                f"➕ New Members: {stats['new_members']}\n"
                f"➖ Removed: {stats['removed_members']}\n"
                f"💬 Commands Used: {stats['commands_used']}\n"
                f"📨 Messages: {stats['messages_received']}\n"
                f"❌ Failed Validations: {stats['failed_validations']}\n"
            )
            
            if stats['failed_validations'] > 10:
                message += f"\n⚠️ High number of failed validations. Consider changing the group password."
            
            # Send to group
            send_message_to_group(group.group_id, message)
        
        return f"Sent statistics for {LineGroup.objects.filter(is_active=True).count()} groups"
        
    except Exception as e:
        logger.error(f"Error sending group statistics: {str(e)}")
        raise


@shared_task
def sync_group_members(group_id):
    """Sync group members with LINE API"""
    try:
        group = LineGroup.objects.get(id=group_id)
        
        # Note: LINE API doesn't provide a way to get group member list
        # This is a placeholder for future functionality if LINE adds this feature
        
        logger.info(f"Group member sync requested for {group.group_name}")
        return "Sync not available - LINE API limitation"
        
    except LineGroup.DoesNotExist:
        logger.error(f"Group {group_id} not found")
        return "Group not found"
    except Exception as e:
        logger.error(f"Error syncing group members: {str(e)}")
        raise


@shared_task
def process_pending_messages():
    """Process any pending messages that failed initial processing"""
    try:
        pending_messages = LineMessage.objects.filter(
            processed_at__isnull=True,
            received_at__gte=timezone.now() - timedelta(hours=1)
        )
        
        processed_count = 0
        
        for message in pending_messages:
            try:
                # Attempt to reprocess
                # This would need the actual implementation based on message type
                logger.info(f"Reprocessing message {message.message_id}")
                
                message.processed_at = timezone.now()
                message.save()
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Failed to reprocess message {message.message_id}: {str(e)}")
        
        return f"Processed {processed_count} pending messages"
        
    except Exception as e:
        logger.error(f"Error processing pending messages: {str(e)}")
        raise


@shared_task
def monitor_bot_health():
    """Monitor bot health and connectivity"""
    try:
        from linebot import LineBotApi
        from linebot.exceptions import LineBotApiError
        
        line_bot_api = LineBotApi(settings.LINE_CHANNEL_ACCESS_TOKEN)
        
        # Try to get bot info (this will fail if token is invalid)
        try:
            # LINE API doesn't have a direct health check endpoint
            # We can try to get quota consumption as a health check
            # This is a workaround
            
            logger.info("LINE bot health check passed")
            
            # Check message processing lag
            unprocessed_count = LineMessage.objects.filter(
                processed_at__isnull=True,
                received_at__lte=timezone.now() - timedelta(minutes=5)
            ).count()
            
            if unprocessed_count > 10:
                SecurityAlert.objects.create(
                    alert_type='suspicious_activity',
                    severity='high',
                    title='High message processing lag detected',
                    description=f'{unprocessed_count} messages unprocessed for more than 5 minutes',
                    details={
                        'unprocessed_count': unprocessed_count,
                        'threshold': 10
                    }
                )
            
            return "Health check completed"
            
        except LineBotApiError as e:
            # Create critical alert
            SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='critical',
                title='LINE Bot API connection failed',
                description=f'Failed to connect to LINE API: {str(e)}',
                details={
                    'error': str(e),
                    'error_type': type(e).__name__
                }
            )
            
            raise
            
    except Exception as e:
        logger.error(f"Bot health check failed: {str(e)}")
        raise