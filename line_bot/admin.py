# line_bot/admin.py

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import LineGroup, GroupMembership, BotCommand, CommandExecution, LineMessage


@admin.register(LineGroup)
class LineGroupAdmin(admin.ModelAdmin):
    """Admin for LINE groups"""
    list_display = [
        'group_name', 'group_id_short', 'active_badge', 'total_members',
        'password_status', 'created_at'
    ]
    list_filter = ['is_active', 'auto_remove_unauthorized', 'created_at']
    search_fields = ['group_name', 'group_id']
    filter_horizontal = ['admins']
    readonly_fields = ['group_id', 'created_at', 'updated_at', 'password_changed_at',
                      'total_members', 'unauthorized_attempts']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('group_name', 'group_id', 'is_active')
        }),
        ('Security Settings', {
            'fields': ('encrypted_password', 'password_expiry_days',
                      'password_changed_at', 'auto_remove_unauthorized')
        }),
        ('Administration', {
            'fields': ('admins', 'max_members')
        }),
        ('Statistics', {
            'fields': ('total_members', 'unauthorized_attempts'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def group_id_short(self, obj):
        return f"{obj.group_id[:20]}..."
    group_id_short.short_description = 'Group ID'
    
    def active_badge(self, obj):
        if obj.is_active:
            return format_html('<span class="badge badge-success">Active</span>')
        return format_html('<span class="badge badge-danger">Inactive</span>')
    active_badge.short_description = 'Status'
    
    def password_status(self, obj):
        if obj.is_password_expired():
            return format_html('<span class="badge badge-danger">Expired</span>')
        days_left = obj.password_expiry_days - (timezone.now() - obj.password_changed_at).days
        if days_left < 7:
            return format_html('<span class="badge badge-warning">{} days left</span>', days_left)
        return format_html('<span class="badge badge-success">Valid</span>')
    password_status.short_description = 'Password'
    
    actions = ['reset_password', 'toggle_auto_remove', 'deactivate_groups']
    
    def reset_password(self, request, queryset):
        count = queryset.update(password_changed_at=timezone.now())
        self.message_user(request, f'Password reset timestamp for {count} groups.')
    reset_password.short_description = 'Reset password timestamp'
    
    def toggle_auto_remove(self, request, queryset):
        for group in queryset:
            group.auto_remove_unauthorized = not group.auto_remove_unauthorized
            group.save()
        self.message_user(request, f'Toggled auto-remove for {queryset.count()} groups.')
    toggle_auto_remove.short_description = 'Toggle auto-remove setting'
    
    def deactivate_groups(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'Deactivated {count} groups.')
    deactivate_groups.short_description = 'Deactivate selected groups'


@admin.register(GroupMembership)
class GroupMembershipAdmin(admin.ModelAdmin):
    """Admin for group memberships"""
    list_display = ['user_display', 'group', 'status_badge', 'joined_at', 'validated_at']
    list_filter = ['validation_status', 'joined_at', 'validated_at']
    search_fields = ['user__email', 'user__line_display_name', 'group__group_name']
    readonly_fields = ['user', 'group', 'line_member_id', 'joined_at',
                      'validated_at', 'removed_at', 'validation_attempts']
    
    def user_display(self, obj):
        return f"{obj.user.line_display_name or obj.user.email}"
    user_display.short_description = 'User'
    
    def status_badge(self, obj):
        colors = {
            'pending': 'warning',
            'validated': 'success',
            'failed': 'danger',
            'removed': 'dark',
        }
        color = colors.get(obj.validation_status, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_validation_status_display()
        )
    status_badge.short_description = 'Status'
    
    def has_add_permission(self, request):
        return False


@admin.register(BotCommand)
class BotCommandAdmin(admin.ModelAdmin):
    """Admin for bot commands"""
    list_display = ['command_display', 'description', 'permission_badge',
                   'active_badge', 'usage_count', 'last_used_at']
    list_filter = ['permission_level', 'is_active', 'created_at']
    search_fields = ['command', 'description']
    readonly_fields = ['usage_count', 'last_used_at', 'last_used_by']
    
    fieldsets = (
        ('Command Information', {
            'fields': ('command', 'description', 'permission_level', 'is_active')
        }),
        ('Usage Statistics', {
            'fields': ('usage_count', 'last_used_at', 'last_used_by'),
            'classes': ('collapse',)
        })
    )
    
    def command_display(self, obj):
        return f"/{obj.command}"
    command_display.short_description = 'Command'
    
    def permission_badge(self, obj):
        colors = {
            'user': 'info',
            'admin': 'warning',
            'superuser': 'danger',
        }
        color = colors.get(obj.permission_level, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_permission_level_display()
        )
    permission_badge.short_description = 'Permission'
    
    def active_badge(self, obj):
        if obj.is_active:
            return format_html('<span class="badge badge-success">Active</span>')
        return format_html('<span class="badge badge-danger">Inactive</span>')
    active_badge.short_description = 'Status'
    
    actions = ['activate_commands', 'deactivate_commands', 'reset_usage_stats']
    
    def activate_commands(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'Activated {count} commands.')
    activate_commands.short_description = 'Activate selected commands'
    
    def deactivate_commands(self, request, queryset):
        count = queryset.update(is_active=False)
        self.message_user(request, f'Deactivated {count} commands.')
    deactivate_commands.short_description = 'Deactivate selected commands'
    
    def reset_usage_stats(self, request, queryset):
        count = queryset.update(usage_count=0, last_used_at=None, last_used_by=None)
        self.message_user(request, f'Reset usage stats for {count} commands.')
    reset_usage_stats.short_description = 'Reset usage statistics'


@admin.register(CommandExecution)
class CommandExecutionAdmin(admin.ModelAdmin):
    """Admin for command executions"""
    list_display = ['command', 'user_display', 'group', 'status_badge',
                   'execution_time_ms', 'executed_at']
    list_filter = ['status', 'executed_at', 'command']
    search_fields = ['user__email', 'user__line_display_name', 'raw_command']
    readonly_fields = ['command', 'user', 'group', 'raw_command', 'parameters',
                      'status', 'error_message', 'response_sent', 'executed_at',
                      'execution_time_ms', 'ip_address']
    date_hierarchy = 'executed_at'
    
    def user_display(self, obj):
        return f"{obj.user.line_display_name or obj.user.email}"
    user_display.short_description = 'User'
    
    def status_badge(self, obj):
        colors = {
            'success': 'success',
            'failed': 'danger',
            'unauthorized': 'warning',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(LineMessage)
class LineMessageAdmin(admin.ModelAdmin):
    """Admin for LINE messages"""
    list_display = ['message_id_short', 'message_type_badge', 'user_display',
                   'group', 'is_command', 'received_at', 'processed_at']
    list_filter = ['message_type', 'is_command', 'received_at', 'processed_at']
    search_fields = ['message_id', 'content', 'user__email', 'user__line_display_name']
    readonly_fields = ['message_id', 'user', 'group', 'message_type', 'content',
                      'raw_event', 'received_at', 'processed_at', 'is_command',
                      'command_execution']
    date_hierarchy = 'received_at'
    
    def message_id_short(self, obj):
        return f"{obj.message_id[:20]}..."
    message_id_short.short_description = 'Message ID'
    
    def user_display(self, obj):
        if obj.user:
            return f"{obj.user.line_display_name or obj.user.email}"
        return "-"
    user_display.short_description = 'User'
    
    def message_type_badge(self, obj):
        colors = {
            'text': 'info',
            'image': 'primary',
            'follow': 'success',
            'unfollow': 'danger',
            'join': 'success',
            'leave': 'danger',
            'member_joined': 'warning',
            'member_left': 'warning',
        }
        color = colors.get(obj.message_type, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_message_type_display()
        )
    message_type_badge.short_description = 'Type'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False