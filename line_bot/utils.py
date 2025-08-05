# line_bot/utils.py

import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from linebot.models import TextSendMessage, QuickReply, QuickReplyButton, MessageAction
from linebot.exceptions import LineBotApiError

from .models import LineGroup, GroupMembership, BotCommand
from accounts.models import CustomUser
from audit_trail.models import AuditLog

logger = logging.getLogger(__name__)


class CommandProcessor:
    """Process LINE bot commands"""
    
    def __init__(self, line_bot_api):
        self.line_bot_api = line_bot_api
        
        # Command handlers mapping
        self.handlers = {
            'help': self.handle_help,
            'status': self.handle_status,
            'setpassword': self.handle_set_password,
            'changepassword': self.handle_change_password,
            'listmembers': self.handle_list_members,
            'removemember': self.handle_remove_member,
            'groupinfo': self.handle_group_info,
            'validateme': self.handle_validate_me,
            'commands': self.handle_list_commands,
            'stats': self.handle_stats,
            'security': self.handle_security_status,
            'approve': self.handle_approve_user,
            'reject': self.handle_reject_user,
            'broadcast': self.handle_broadcast,
        }
    
    def process_command(self, command_name, args, event, user, group):
        """Process a command and return response"""
        
        handler = self.handlers.get(command_name)
        if not handler:
            return self.send_reply(event, f"Unknown command: /{command_name}")
        
        try:
            return handler(args, event, user, group)
        except Exception as e:
            logger.error(f"Command handler error: {command_name} - {str(e)}")
            raise
    
    def send_reply(self, event, text):
        """Send reply message"""
        try:
            self.line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=text)
            )
            return text
        except LineBotApiError as e:
            logger.error(f"Failed to send reply: {str(e)}")
            raise
    
    def handle_help(self, args, event, user, group):
        """Handle /help command"""
        
        # Get available commands for user
        if user.is_superuser:
            commands = BotCommand.objects.filter(is_active=True)
        elif user.is_admin:
            commands = BotCommand.objects.filter(
                is_active=True,
                permission_level__in=['admin', 'user']
            )
        else:
            commands = BotCommand.objects.filter(
                is_active=True,
                permission_level='user'
            )
        
        help_text = "📋 Available Commands:\n\n"
        
        for cmd in commands:
            help_text += f"/{cmd.command} - {cmd.description}\n"
        
        help_text += "\n💡 For more info on a specific command, use: /help <command>"
        
        return self.send_reply(event, help_text)
    
    def handle_status(self, args, event, user, group):
        """Handle /status command"""
        
        status_text = f"👤 User Status\n\n"
        status_text += f"Email: {user.email}\n"
        status_text += f"Name: {user.get_full_name()}\n"
        status_text += f"Type: {user.get_user_type_display()}\n"
        status_text += f"Approved: {'✅ Yes' if user.is_approved else '⏳ Pending'}\n"
        status_text += f"MFA Enabled: {'✅ Yes' if user.mfa_enabled else '❌ No'}\n"
        
        if group:
            membership = GroupMembership.objects.filter(
                user=user,
                group=group
            ).first()
            
            if membership:
                status_text += f"\n📱 Group Status\n"
                status_text += f"Group: {group.group_name}\n"
                status_text += f"Validated: {'✅ Yes' if membership.validation_status == 'validated' else '❌ No'}\n"
                status_text += f"Joined: {membership.joined_at.strftime('%Y-%m-%d %H:%M')}\n"
        
        return self.send_reply(event, status_text)
    
    def handle_set_password(self, args, event, user, group):
        """Handle /setpassword command (admin only)"""
        
        if not group:
            return self.send_reply(event, "This command can only be used in a group.")
        
        if not args:
            return self.send_reply(event, "Usage: /setpassword <new_password>")
        
        # Check if user is group admin
        if not group.admins.filter(id=user.id).exists() and not user.is_superuser:
            return self.send_reply(event, "Only group admins can set the password.")
        
        new_password = ' '.join(args)
        
        # Validate password strength
        if len(new_password) < 8:
            return self.send_reply(event, "Password must be at least 8 characters long.")
        
        # Set password
        group.set_password(new_password)
        
        # Log password change
        AuditLog.log(
            action='group_password_changed',
            user=user,
            severity='info',
            message=f'Group password changed for {group.group_name}',
            content_object=group
        )
        
        return self.send_reply(event, "✅ Group password has been set successfully.")
    
    def handle_change_password(self, args, event, user, group):
        """Handle /changepassword command (admin only)"""
        return self.handle_set_password(args, event, user, group)
    
    def handle_list_members(self, args, event, user, group):
        """Handle /listmembers command"""
        
        if not group:
            return self.send_reply(event, "This command can only be used in a group.")
        
        # Check permissions
        if not group.admins.filter(id=user.id).exists() and not user.is_admin:
            return self.send_reply(event, "Only admins can list group members.")
        
        # Get members
        memberships = GroupMembership.objects.filter(
            group=group,
            validation_status='validated'
        ).select_related('user')
        
        members_text = f"👥 Group Members ({memberships.count()})\n\n"
        
        for membership in memberships:
            member = membership.user
            members_text += f"• {member.line_display_name or member.email}\n"
            if member.is_admin:
                members_text += "  👑 Admin\n"
            members_text += f"  Joined: {membership.joined_at.strftime('%Y-%m-%d')}\n\n"
        
        return self.send_reply(event, members_text)
    
    def handle_remove_member(self, args, event, user, group):
        """Handle /removemember command (admin only)"""
        
        if not group:
            return self.send_reply(event, "This command can only be used in a group.")
        
        if not args:
            return self.send_reply(event, "Usage: /removemember <user_id_or_name>")
        
        # Check permissions
        if not group.admins.filter(id=user.id).exists() and not user.is_superuser:
            return self.send_reply(event, "Only group admins can remove members.")
        
        target_identifier = ' '.join(args)
        
        # Find target member
        membership = GroupMembership.objects.filter(
            group=group,
            user__line_display_name__icontains=target_identifier
        ).first()
        
        if not membership:
            return self.send_reply(event, "Member not found.")
        
        target_user = membership.user
        
        # Don't allow removing admins
        if target_user.is_admin:
            return self.send_reply(event, "Cannot remove admin users.")
        
        # Remove from LINE group
        try:
            if hasattr(event.source, 'group_id'):
                self.line_bot_api.leave_group(event.source.group_id)
        except:
            pass
        
        # Mark membership as removed
        membership.mark_as_removed()
        
        # Log removal
        AuditLog.log(
            action='group_member_removed',
            user=user,
            severity='warning',
            message=f'{target_user.line_display_name} removed from {group.group_name} by {user.email}',
            content_object=group,
            metadata={'removed_user': str(target_user.id)}
        )
        
        return self.send_reply(event, f"✅ {target_user.line_display_name} has been removed from the group.")
    
    def handle_group_info(self, args, event, user, group):
        """Handle /groupinfo command"""
        
        if not group:
            return self.send_reply(event, "This command can only be used in a group.")
        
        info_text = f"📱 Group Information\n\n"
        info_text += f"Name: {group.group_name}\n"
        info_text += f"Active: {'✅ Yes' if group.is_active else '❌ No'}\n"
        info_text += f"Password Protected: ✅ Yes\n"
        info_text += f"Auto-Remove: {'✅ Yes' if group.auto_remove_unauthorized else '❌ No'}\n"
        info_text += f"Total Members: {group.total_members}\n"
        info_text += f"Created: {group.created_at.strftime('%Y-%m-%d')}\n"
        
        if user.is_admin:
            info_text += f"\n🔐 Security Stats\n"
            info_text += f"Password Age: {(timezone.now() - group.password_changed_at).days} days\n"
            info_text += f"Failed Attempts: {group.unauthorized_attempts}\n"
            info_text += f"Admins: {group.admins.count()}\n"
        
        return self.send_reply(event, info_text)
    
    def handle_validate_me(self, args, event, user, group):
        """Handle /validateme command - for users to validate with group password"""
        
        if not args:
            return self.send_reply(event, "Usage: /validateme <group_password>")
        
        password = ' '.join(args)
        
        # This should be sent privately, not in group
        if hasattr(event.source, 'group_id'):
            # Delete the message if possible
            return self.send_reply(
                event, 
                "⚠️ Please send the password in a private message to the bot, not in the group!"
            )
        
        # Find pending memberships
        pending_memberships = GroupMembership.objects.filter(
            user=user,
            validation_status='pending'
        )
        
        validated_groups = []
        
        for membership in pending_memberships:
            if membership.group.check_password(password):
                membership.validate_membership()
                validated_groups.append(membership.group.group_name)
                
                # Update member count
                membership.group.total_members = GroupMembership.objects.filter(
                    group=membership.group,
                    validation_status='validated'
                ).count()
                membership.group.save()
        
        if validated_groups:
            return self.send_reply(
                event,
                f"✅ Successfully validated for groups: {', '.join(validated_groups)}"
            )
        else:
            # Log failed attempt
            for membership in pending_memberships:
                membership.validation_attempts += 1
                membership.save()
                membership.group.increment_unauthorized_attempts()
            
            return self.send_reply(event, "❌ Invalid password.")
    
    def handle_list_commands(self, args, event, user, group):
        """Handle /commands command - list all available commands"""
        
        # Group commands by permission level
        superuser_cmds = BotCommand.objects.filter(
            is_active=True,
            permission_level='superuser'
        )
        admin_cmds = BotCommand.objects.filter(
            is_active=True,
            permission_level='admin'
        )
        user_cmds = BotCommand.objects.filter(
            is_active=True,
            permission_level='user'
        )
        
        commands_text = "📋 All Available Commands\n\n"
        
        if user_cmds.exists():
            commands_text += "👤 User Commands:\n"
            for cmd in user_cmds:
                commands_text += f"  /{cmd.command} - {cmd.description}\n"
            commands_text += "\n"
        
        if user.is_admin or user.is_superuser:
            if admin_cmds.exists():
                commands_text += "👑 Admin Commands:\n"
                for cmd in admin_cmds:
                    commands_text += f"  /{cmd.command} - {cmd.description}\n"
                commands_text += "\n"
        
        if user.is_superuser:
            if superuser_cmds.exists():
                commands_text += "🔐 Superuser Commands:\n"
                for cmd in superuser_cmds:
                    commands_text += f"  /{cmd.command} - {cmd.description}\n"
        
        return self.send_reply(event, commands_text)
    
    def handle_stats(self, args, event, user, group):
        """Handle /stats command - show bot statistics"""
        
        if not user.is_admin:
            return self.send_reply(event, "This command is for admins only.")
        
        # Gather statistics
        from django.db.models import Count
        total_users = CustomUser.objects.filter(line_user_id__isnull=False).count()
        approved_users = CustomUser.objects.filter(
            line_user_id__isnull=False,
            is_approved=True
        ).count()
        total_groups = LineGroup.objects.filter(is_active=True).count()
        total_commands = CommandExecution.objects.count()
        
        # Recent activity
        last_24h = timezone.now() - timedelta(hours=24)
        recent_commands = CommandExecution.objects.filter(
            executed_at__gte=last_24h
        ).count()
        recent_messages = LineMessage.objects.filter(
            received_at__gte=last_24h
        ).count()
        
        stats_text = "📊 Bot Statistics\n\n"
        stats_text += f"👥 Users: {total_users} ({approved_users} approved)\n"
        stats_text += f"📱 Active Groups: {total_groups}\n"
        stats_text += f"💬 Total Commands: {total_commands}\n"
        stats_text += f"\n📈 Last 24 Hours:\n"
        stats_text += f"  Commands: {recent_commands}\n"
        stats_text += f"  Messages: {recent_messages}\n"
        
        if group:
            # Group-specific stats
            group_members = GroupMembership.objects.filter(
                group=group,
                validation_status='validated'
            ).count()
            group_commands = CommandExecution.objects.filter(
                group=group
            ).count()
            
            stats_text += f"\n📱 This Group:\n"
            stats_text += f"  Members: {group_members}\n"
            stats_text += f"  Commands Used: {group_commands}\n"
        
        return self.send_reply(event, stats_text)
    
    def handle_security_status(self, args, event, user, group):
        """Handle /security command - show security status"""
        
        if not user.is_admin:
            return self.send_reply(event, "This command is for admins only.")
        
        # Get recent security alerts
        from security_suite.models import SecurityAlert
        recent_alerts = SecurityAlert.objects.filter(
            status='new'
        ).order_by('-created_at')[:5]
        
        security_text = "🔐 Security Status\n\n"
        
        if recent_alerts:
            security_text += "⚠️ Recent Alerts:\n"
            for alert in recent_alerts:
                security_text += f"• [{alert.get_severity_display()}] {alert.title}\n"
                security_text += f"  {alert.created_at.strftime('%Y-%m-%d %H:%M')}\n"
        else:
            security_text += "✅ No active security alerts\n"
        
        # Failed login attempts
        last_hour = timezone.now() - timedelta(hours=1)
        from audit_trail.models import AuditLog
        failed_logins = AuditLog.objects.filter(
            action='login_failed',
            timestamp__gte=last_hour
        ).count()
        
        security_text += f"\n🚫 Failed Logins (1h): {failed_logins}\n"
        
        # Blocked IPs
        from security_suite.models import IPBlacklist
        blocked_ips = IPBlacklist.objects.filter(is_active=True).count()
        security_text += f"🚫 Blocked IPs: {blocked_ips}\n"
        
        return self.send_reply(event, security_text)
    
    def handle_approve_user(self, args, event, user, group):
        """Handle /approve command - approve pending user"""
        
        if not user.is_admin:
            return self.send_reply(event, "This command is for admins only.")
        
        if not args:
            # Show pending users
            pending_users = CustomUser.objects.filter(
                approval_status='pending',
                line_user_id__isnull=False
            ).order_by('-date_joined')[:10]
            
            if not pending_users:
                return self.send_reply(event, "No pending user approvals.")
            
            pending_text = "⏳ Pending Approvals:\n\n"
            for pending_user in pending_users:
                pending_text += f"• {pending_user.line_display_name} ({pending_user.email})\n"
                pending_text += f"  ID: {pending_user.line_user_id[:8]}...\n"
                pending_text += f"  Joined: {pending_user.date_joined.strftime('%Y-%m-%d')}\n\n"
            
            pending_text += "Use: /approve <user_id> to approve"
            
            return self.send_reply(event, pending_text)
        
        # Approve specific user
        target_id = args[0]
        
        try:
            target_user = CustomUser.objects.get(
                Q(line_user_id__startswith=target_id) |
                Q(email__icontains=target_id),
                approval_status='pending'
            )
            
            target_user.approve_user(user)
            
            # Send notification to user
            try:
                self.line_bot_api.push_message(
                    target_user.line_user_id,
                    TextSendMessage(
                        text="✅ Your account has been approved! You can now use all bot features."
                    )
                )
            except:
                pass
            
            return self.send_reply(
                event,
                f"✅ Approved user: {target_user.line_display_name} ({target_user.email})"
            )
            
        except CustomUser.DoesNotExist:
            return self.send_reply(event, "User not found or already approved.")
        except CustomUser.MultipleObjectsReturned:
            return self.send_reply(event, "Multiple users found. Please be more specific.")
    
    def handle_reject_user(self, args, event, user, group):
        """Handle /reject command - reject pending user"""
        
        if not user.is_admin:
            return self.send_reply(event, "This command is for admins only.")
        
        if not args:
            return self.send_reply(event, "Usage: /reject <user_id>")
        
        target_id = args[0]
        
        try:
            target_user = CustomUser.objects.get(
                Q(line_user_id__startswith=target_id) |
                Q(email__icontains=target_id),
                approval_status='pending'
            )
            
            target_user.reject_user(user)
            
            return self.send_reply(
                event,
                f"❌ Rejected user: {target_user.line_display_name} ({target_user.email})"
            )
            
        except CustomUser.DoesNotExist:
            return self.send_reply(event, "User not found.")
        except CustomUser.MultipleObjectsReturned:
            return self.send_reply(event, "Multiple users found. Please be more specific.")
    
    def handle_broadcast(self, args, event, user, group):
        """Handle /broadcast command - send message to all groups"""
        
        if not user.is_superuser:
            return self.send_reply(event, "This command is for superusers only.")
        
        if not args:
            return self.send_reply(event, "Usage: /broadcast <message>")
        
        message = ' '.join(args)
        
        # Get all active groups
        active_groups = LineGroup.objects.filter(is_active=True)
        success_count = 0
        
        for target_group in active_groups:
            try:
                self.line_bot_api.push_message(
                    target_group.group_id,
                    TextSendMessage(
                        text=f"📢 Broadcast Message:\n\n{message}\n\n- Security Bot Admin"
                    )
                )
                success_count += 1
            except LineBotApiError as e:
                logger.error(f"Failed to broadcast to {target_group.group_id}: {str(e)}")
        
        # Log broadcast
        AuditLog.log(
            action='message_sent',
            user=user,
            severity='info',
            message=f'Broadcast sent to {success_count}/{active_groups.count()} groups',
            metadata={
                'message': message[:100],
                'groups_count': active_groups.count(),
                'success_count': success_count
            }
        )
        
        return self.send_reply(
            event,
            f"✅ Broadcast sent to {success_count}/{active_groups.count()} groups."
        )


def get_line_user_profile(user_id):
    """Get user profile from LINE API"""
    try:
        from linebot import LineBotApi
        line_bot_api = LineBotApi(settings.LINE_CHANNEL_ACCESS_TOKEN)
        
        profile = line_bot_api.get_profile(user_id)
        return {
            'displayName': profile.display_name,
            'userId': profile.user_id,
            'pictureUrl': getattr(profile, 'picture_url', None),
            'statusMessage': getattr(profile, 'status_message', None)
        }
    except Exception as e:
        logger.error(f"Failed to get LINE profile for {user_id}: {str(e)}")
        return None


def send_message_to_user(user_id, message):
    """Send a message to a specific user"""
    try:
        from linebot import LineBotApi
        line_bot_api = LineBotApi(settings.LINE_CHANNEL_ACCESS_TOKEN)
        
        line_bot_api.push_message(
            user_id,
            TextSendMessage(text=message)
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send message to {user_id}: {str(e)}")
        return False


def send_message_to_group(group_id, message):
    """Send a message to a specific group"""
    try:
        from linebot import LineBotApi
        line_bot_api = LineBotApi(settings.LINE_CHANNEL_ACCESS_TOKEN)
        
        line_bot_api.push_message(
            group_id,
            TextSendMessage(text=message)
        )
        return True
    except Exception as e:
        logger.error(f"Failed to send message to group {group_id}: {str(e)}")
        return False


def remove_user_from_group(group_id, user_id):
    """Remove a user from a LINE group"""
    try:
        from linebot import LineBotApi
        line_bot_api = LineBotApi(settings.LINE_CHANNEL_ACCESS_TOKEN)
        
        # Note: LINE API doesn't support removing specific users
        # The bot can only leave the group itself
        # This is a limitation of the LINE Messaging API
        
        logger.warning(f"Cannot remove user {user_id} from group {group_id} - LINE API limitation")
        return False
    except Exception as e:
        logger.error(f"Error in remove_user_from_group: {str(e)}")
        return False