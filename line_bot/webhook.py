# line_bot/webhook.py

import json
import logging
from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest
from django.views import View
from django.utils import timezone
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError, LineBotApiError
from linebot.models import (
    MessageEvent, TextMessage, TextSendMessage,
    JoinEvent, LeaveEvent, MemberJoinedEvent, MemberLeftEvent,
    FollowEvent, UnfollowEvent, PostbackEvent
)

from accounts.models import CustomUser
from .models import LineGroup, GroupMembership, LineMessage, BotCommand, CommandExecution
from .utils import CommandProcessor
from security_suite.models import SecurityAlert
from audit_trail.models import AuditLog

logger = logging.getLogger(__name__)

# Initialize LINE Bot SDK
line_bot_api = LineBotApi(settings.LINE_CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(settings.LINE_CHANNEL_SECRET)


class LineWebhookView(View):
    """Handle LINE webhook events"""
    
    def post(self, request):
        # Get request body and signature
        body = request.body.decode('utf-8')
        signature = request.META.get('HTTP_X_LINE_SIGNATURE', '')
        
        # Log webhook received
        logger.info(f"Webhook received: {body[:200]}...")
        
        # Verify webhook signature
        try:
            handler.handle(body, signature)
        except InvalidSignatureError:
            logger.error("Invalid signature")
            return HttpResponseBadRequest("Invalid signature")
        except Exception as e:
            logger.error(f"Webhook handling error: {str(e)}")
            return HttpResponseBadRequest(str(e))
        
        return HttpResponse("OK")


@handler.add(MessageEvent, message=TextMessage)
def handle_text_message(event):
    """Handle text messages"""
    try:
        # Store message
        message_record = LineMessage.objects.create(
            message_id=event.message.id,
            message_type='text',
            content=event.message.text,
            raw_event=event.as_json_dict()
        )
        
        # Get or create user
        user = get_or_create_line_user(event.source.user_id)
        if user:
            message_record.user = user
        
        # Check if in group
        group = None
        if hasattr(event.source, 'group_id'):
            group = get_line_group(event.source.group_id)
            message_record.group = group
        
        message_record.save()
        
        # Check if it's a command
        if event.message.text.startswith('/'):
            handle_command(event, user, group, message_record)
        
        message_record.processed_at = timezone.now()
        message_record.save()
        
    except Exception as e:
        logger.error(f"Error handling text message: {str(e)}")
        
        # Send error message to user
        try:
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text="An error occurred processing your message.")
            )
        except:
            pass


@handler.add(JoinEvent)
def handle_join_event(event):
    """Handle bot joining a group"""
    try:
        group_id = event.source.group_id
        
        # Create or update group
        group, created = LineGroup.objects.get_or_create(
            group_id=group_id,
            defaults={
                'group_name': f'Group_{group_id[:8]}',
                'encrypted_password': ''  # Will be set by admin
            }
        )
        
        # Store event
        LineMessage.objects.create(
            message_id=f'join_{group_id}_{timezone.now().timestamp()}',
            message_type='join',
            group=group,
            raw_event=event.as_json_dict(),
            processed_at=timezone.now()
        )
        
        # Send welcome message
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(
                text="Hello! I'm the Security Bot. An admin needs to set up a password for this group before members can join.\n\n" +
                     "Admins can use /setpassword <password> to set the group password."
            )
        )
        
        # Log the join
        AuditLog.log(
            action='group_created',
            severity='info',
            message=f'Bot joined LINE group {group_id}',
            metadata={'group_id': group_id, 'created': created}
        )
        
    except Exception as e:
        logger.error(f"Error handling join event: {str(e)}")


@handler.add(MemberJoinedEvent)
def handle_member_joined(event):
    """Handle new member joining group"""
    try:
        group_id = event.source.group_id
        group = get_line_group(group_id)
        
        if not group:
            return
        
        for member in event.joined.members:
            # Store event
            LineMessage.objects.create(
                message_id=f'member_join_{member.user_id}_{timezone.now().timestamp()}',
                message_type='member_joined',
                group=group,
                raw_event=event.as_json_dict(),
                processed_at=timezone.now()
            )
            
            # Get or create user
            user = get_or_create_line_user(member.user_id)
            
            # Create membership record
            membership, created = GroupMembership.objects.get_or_create(
                user=user,
                group=group,
                defaults={
                    'line_member_id': member.user_id,
                    'validation_status': 'pending'
                }
            )
            
            if created and group.auto_remove_unauthorized:
                # Send password request
                try:
                    line_bot_api.push_message(
                        member.user_id,
                        TextSendMessage(
                            text=f"Welcome! This group requires a password. Please send me the password in a private message to join.\n\n" +
                                 f"You have 5 minutes to provide the correct password or you will be removed from the group."
                        )
                    )
                    
                    # Schedule removal check
                    from .tasks import check_member_validation
                    check_member_validation.apply_async(
                        args=[str(membership.id)],
                        countdown=300  # 5 minutes
                    )
                    
                except LineBotApiError as e:
                    logger.error(f"Failed to send password request: {str(e)}")
            
            # Log member join
            AuditLog.log(
                action='group_member_added',
                user=user,
                severity='info',
                message=f'User {user.line_display_name or user.line_user_id} joined group {group.group_name}',
                content_object=group,
                metadata={'auto_remove': group.auto_remove_unauthorized}
            )
            
    except Exception as e:
        logger.error(f"Error handling member joined: {str(e)}")


@handler.add(FollowEvent)
def handle_follow_event(event):
    """Handle user following the bot"""
    try:
        user_id = event.source.user_id
        
        # Get or create user
        user = get_or_create_line_user(user_id)
        
        # Store event
        LineMessage.objects.create(
            message_id=f'follow_{user_id}_{timezone.now().timestamp()}',
            message_type='follow',
            user=user,
            raw_event=event.as_json_dict(),
            processed_at=timezone.now()
        )
        
        # Send welcome message
        line_bot_api.reply_message(
            event.reply_token,
            TextSendMessage(
                text="Welcome! I'm the Security Bot. I help manage secure LINE groups.\n\n" +
                     "Available commands:\n" +
                     "/help - Show available commands\n" +
                     "/status - Check your account status"
            )
        )
        
    except Exception as e:
        logger.error(f"Error handling follow event: {str(e)}")


def handle_command(event, user, group, message_record):
    """Process bot commands"""
    try:
        # Parse command
        parts = event.message.text.strip().split()
        command_name = parts[0][1:].lower()  # Remove / prefix
        args = parts[1:] if len(parts) > 1 else []
        
        # Get command
        try:
            command = BotCommand.objects.get(command=command_name, is_active=True)
        except BotCommand.DoesNotExist:
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=f"Unknown command: /{command_name}")
            )
            return
        
        # Check permissions
        if not command.can_execute(user):
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text="You don't have permission to use this command.")
            )
            
            # Log unauthorized attempt
            CommandExecution.objects.create(
                command=command,
                user=user,
                group=group,
                raw_command=event.message.text,
                status='unauthorized',
                error_message='Insufficient permissions'
            )
            
            # Create security alert for admin commands
            if command.permission_level in ['admin', 'superuser']:
                SecurityAlert.objects.create(
                    alert_type='unauthorized_access',
                    severity='medium',
                    title=f'Unauthorized command attempt by {user.email}',
                    description=f'User tried to execute admin command: /{command_name}',
                    user=user,
                    details={
                        'command': command_name,
                        'group_id': group.group_id if group else None,
                        'user_type': user.user_type
                    }
                )
            
            return
        
        # Mark message as command
        message_record.is_command = True
        message_record.save()
        
        # Process command
        processor = CommandProcessor(line_bot_api)
        start_time = timezone.now()
        
        try:
            response = processor.process_command(command_name, args, event, user, group)
            
            # Record successful execution
            execution = CommandExecution.objects.create(
                command=command,
                user=user,
                group=group,
                raw_command=event.message.text,
                parameters={'args': args},
                status='success',
                response_sent=response[:1000] if response else '',
                execution_time_ms=int((timezone.now() - start_time).total_seconds() * 1000)
            )
            
            message_record.command_execution = execution
            message_record.save()
            
            # Update command usage
            command.record_usage(user)
            
        except Exception as e:
            # Record failed execution
            CommandExecution.objects.create(
                command=command,
                user=user,
                group=group,
                raw_command=event.message.text,
                parameters={'args': args},
                status='failed',
                error_message=str(e),
                execution_time_ms=int((timezone.now() - start_time).total_seconds() * 1000)
            )
            
            # Send error message
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text=f"Command failed: {str(e)}")
            )
            
            # Log error
            logger.error(f"Command execution failed: {command_name} - {str(e)}")
            
    except Exception as e:
        logger.error(f"Error handling command: {str(e)}")
        
        try:
            line_bot_api.reply_message(
                event.reply_token,
                TextSendMessage(text="An error occurred processing your command.")
            )
        except:
            pass


def get_or_create_line_user(line_user_id):
    """Get or create user from LINE user ID"""
    try:
        # Try to get existing user
        user = CustomUser.objects.filter(line_user_id=line_user_id).first()
        
        if not user:
            # Get profile from LINE
            try:
                profile = line_bot_api.get_profile(line_user_id)
                display_name = profile.display_name
            except:
                display_name = f'LINE User {line_user_id[:8]}'
            
            # Create new user
            user = CustomUser.objects.create(
                email=f'{line_user_id}@line.local',  # Placeholder email
                line_user_id=line_user_id,
                line_display_name=display_name,
                is_approved=False,  # Require admin approval
                approval_status='pending'
            )
            
            # Log new user
            AuditLog.log(
                action='user_created',
                user=user,
                severity='info',
                message=f'New LINE user created: {display_name}',
                metadata={'line_user_id': line_user_id}
            )
        
        return user
        
    except Exception as e:
        logger.error(f"Error getting/creating LINE user: {str(e)}")
        return None


def get_line_group(group_id):
    """Get LINE group by ID"""
    try:
        return LineGroup.objects.filter(group_id=group_id).first()
    except Exception as e:
        logger.error(f"Error getting LINE group: {str(e)}")
        return None