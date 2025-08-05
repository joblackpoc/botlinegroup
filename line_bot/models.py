# line_bot/models.py

from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from cryptography.fernet import Fernet
import uuid
from datetime import timedelta


class LineGroup(models.Model):
    """Model for LINE groups with password protection"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    group_id = models.CharField(_('LINE group ID'), max_length=255, unique=True)
    group_name = models.CharField(_('group name'), max_length=255, blank=True)
    encrypted_password = models.CharField(_('encrypted password'), max_length=255)
    
    # Group settings
    is_active = models.BooleanField(_('active'), default=True)
    auto_remove_unauthorized = models.BooleanField(
        _('auto remove unauthorized users'),
        default=True
    )
    password_expiry_days = models.IntegerField(
        _('password expiry days'),
        default=30
    )
    max_members = models.IntegerField(_('max members'), default=100)
    
    # Admin assignments
    admins = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='admin_groups',
        blank=True
    )
    
    # Timestamps
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    password_changed_at = models.DateTimeField(_('password changed at'), default=timezone.now)
    
    # Statistics
    total_members = models.IntegerField(_('total members'), default=0)
    unauthorized_attempts = models.IntegerField(_('unauthorized attempts'), default=0)
    
    class Meta:
        verbose_name = _('LINE group')
        verbose_name_plural = _('LINE groups')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['group_id']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return self.group_name or self.group_id
    
    def set_password(self, password):
        """Encrypt and set group password"""
        fernet = Fernet(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        self.encrypted_password = fernet.encrypt(password.encode()).decode()
        self.password_changed_at = timezone.now()
        self.save()
    
    def check_password(self, password):
        """Check if provided password is correct"""
        fernet = Fernet(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        try:
            decrypted = fernet.decrypt(self.encrypted_password.encode()).decode()
            return password == decrypted
        except:
            return False
    
    def is_password_expired(self):
        """Check if group password has expired"""
        if self.password_expiry_days == 0:
            return False
        expiry_date = self.password_changed_at + timedelta(days=self.password_expiry_days)
        return timezone.now() > expiry_date
    
    def increment_unauthorized_attempts(self):
        """Increment unauthorized access attempts counter"""
        self.unauthorized_attempts += 1
        self.save()


class GroupMembership(models.Model):
    """Track group memberships and validations"""
    
    VALIDATION_STATUS_CHOICES = (
        ('pending', _('Pending')),
        ('validated', _('Validated')),
        ('failed', _('Failed')),
        ('removed', _('Removed')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='group_memberships'
    )
    group = models.ForeignKey(
        LineGroup,
        on_delete=models.CASCADE,
        related_name='memberships'
    )
    
    # Membership details
    line_member_id = models.CharField(_('LINE member ID'), max_length=255)
    joined_at = models.DateTimeField(_('joined at'), default=timezone.now)
    validated_at = models.DateTimeField(_('validated at'), null=True, blank=True)
    removed_at = models.DateTimeField(_('removed at'), null=True, blank=True)
    
    # Validation
    validation_status = models.CharField(
        _('validation status'),
        max_length=20,
        choices=VALIDATION_STATUS_CHOICES,
        default='pending'
    )
    validation_attempts = models.IntegerField(_('validation attempts'), default=0)
    
    class Meta:
        verbose_name = _('group membership')
        verbose_name_plural = _('group memberships')
        unique_together = [['user', 'group']]
        ordering = ['-joined_at']
        indexes = [
            models.Index(fields=['group', 'validation_status']),
            models.Index(fields=['user', 'validation_status']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.group.group_name}"
    
    def validate_membership(self):
        """Mark membership as validated"""
        self.validation_status = 'validated'
        self.validated_at = timezone.now()
        self.save()
    
    def mark_as_removed(self):
        """Mark membership as removed"""
        self.validation_status = 'removed'
        self.removed_at = timezone.now()
        self.save()


class BotCommand(models.Model):
    """Available bot commands"""
    
    PERMISSION_LEVEL_CHOICES = (
        ('superuser', _('Superuser Only')),
        ('admin', _('Admin Only')),
        ('user', _('All Users')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    command = models.CharField(_('command'), max_length=50, unique=True)
    description = models.TextField(_('description'))
    permission_level = models.CharField(
        _('permission level'),
        max_length=20,
        choices=PERMISSION_LEVEL_CHOICES,
        default='admin'
    )
    is_active = models.BooleanField(_('active'), default=True)
    
    # Usage statistics
    usage_count = models.IntegerField(_('usage count'), default=0)
    last_used_at = models.DateTimeField(_('last used at'), null=True, blank=True)
    last_used_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='last_used_commands'
    )
    
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    
    class Meta:
        verbose_name = _('bot command')
        verbose_name_plural = _('bot commands')
        ordering = ['command']
    
    def __str__(self):
        return f"/{self.command}"
    
    def can_execute(self, user):
        """Check if user can execute this command"""
        if not self.is_active:
            return False
        
        if self.permission_level == 'superuser':
            return user.is_superuser
        elif self.permission_level == 'admin':
            return user.is_admin
        else:
            return True
    
    def record_usage(self, user):
        """Record command usage"""
        self.usage_count += 1
        self.last_used_at = timezone.now()
        self.last_used_by = user
        self.save()


class CommandExecution(models.Model):
    """Log of command executions"""
    
    STATUS_CHOICES = (
        ('success', _('Success')),
        ('failed', _('Failed')),
        ('unauthorized', _('Unauthorized')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    command = models.ForeignKey(
        BotCommand,
        on_delete=models.CASCADE,
        related_name='executions'
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='command_executions'
    )
    group = models.ForeignKey(
        LineGroup,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='command_executions'
    )
    
    # Execution details
    raw_command = models.TextField(_('raw command'))
    parameters = models.JSONField(_('parameters'), default=dict, blank=True)
    status = models.CharField(
        _('status'),
        max_length=20,
        choices=STATUS_CHOICES
    )
    error_message = models.TextField(_('error message'), blank=True)
    
    # Response
    response_sent = models.TextField(_('response sent'), blank=True)
    
    # Metadata
    executed_at = models.DateTimeField(_('executed at'), auto_now_add=True)
    execution_time_ms = models.IntegerField(_('execution time (ms)'), default=0)
    ip_address = models.GenericIPAddressField(_('IP address'), null=True, blank=True)
    
    class Meta:
        verbose_name = _('command execution')
        verbose_name_plural = _('command executions')
        ordering = ['-executed_at']
        indexes = [
            models.Index(fields=['user', '-executed_at']),
            models.Index(fields=['command', '-executed_at']),
            models.Index(fields=['status', '-executed_at']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.command.command} - {self.status}"


class LineMessage(models.Model):
    """Store LINE messages for audit purposes"""
    
    MESSAGE_TYPE_CHOICES = (
        ('text', _('Text')),
        ('image', _('Image')),
        ('video', _('Video')),
        ('audio', _('Audio')),
        ('file', _('File')),
        ('location', _('Location')),
        ('sticker', _('Sticker')),
        ('follow', _('Follow')),
        ('unfollow', _('Unfollow')),
        ('join', _('Join')),
        ('leave', _('Leave')),
        ('member_joined', _('Member Joined')),
        ('member_left', _('Member Left')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message_id = models.CharField(_('LINE message ID'), max_length=255, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='line_messages'
    )
    group = models.ForeignKey(
        LineGroup,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='messages'
    )
    
    # Message details
    message_type = models.CharField(
        _('message type'),
        max_length=20,
        choices=MESSAGE_TYPE_CHOICES
    )
    content = models.TextField(_('content'), blank=True)
    raw_event = models.JSONField(_('raw event'), default=dict)
    
    # Timestamps
    received_at = models.DateTimeField(_('received at'), auto_now_add=True)
    processed_at = models.DateTimeField(_('processed at'), null=True, blank=True)
    
    # Processing
    is_command = models.BooleanField(_('is command'), default=False)
    command_execution = models.ForeignKey(
        CommandExecution,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='source_message'
    )
    
    class Meta:
        verbose_name = _('LINE message')
        verbose_name_plural = _('LINE messages')
        ordering = ['-received_at']
        indexes = [
            models.Index(fields=['user', '-received_at']),
            models.Index(fields=['group', '-received_at']),
            models.Index(fields=['message_type', '-received_at']),
        ]
    
    def __str__(self):
        return f"{self.message_type} - {self.message_id}"