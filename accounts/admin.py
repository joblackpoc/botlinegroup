# accounts/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import CustomUser, PasswordHistory


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    """Enhanced admin for CustomUser"""
    
    list_display = [
        'email', 'full_name', 'user_type_badge', 'approval_badge',
        'mfa_badge', 'last_activity', 'date_joined'
    ]
    list_filter = [
        'is_staff', 'is_superuser', 'is_active', 'is_approved',
        'approval_status', 'user_type', 'mfa_enabled', 'date_joined'
    ]
    search_fields = ['email', 'first_name', 'last_name', 'line_user_id', 'line_display_name']
    ordering = ['-date_joined']
    
    fieldsets = (
        (None, {
            'fields': ('email', 'password')
        }),
        (_('Personal info'), {
            'fields': ('first_name', 'last_name', 'line_user_id', 'line_display_name')
        }),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'user_type',
                      'groups', 'user_permissions')
        }),
        (_('Approval'), {
            'fields': ('is_approved', 'approval_status', 'approved_at', 'approved_by')
        }),
        (_('Security'), {
            'fields': ('mfa_enabled', 'mfa_enforced_at', 'failed_login_attempts',
                      'last_failed_login', 'last_password_change')
        }),
        (_('Important dates'), {
            'fields': ('last_login', 'last_activity', 'date_joined')
        }),
        (_('IP Tracking'), {
            'fields': ('registration_ip', 'last_login_ip'),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name',
                      'user_type', 'is_approved'),
        }),
    )
    
    def full_name(self, obj):
        return obj.get_full_name()
    full_name.short_description = 'Full Name'
    
    def user_type_badge(self, obj):
        colors = {
            'admin': 'success',
            'user': 'info',
        }
        if obj.is_superuser:
            return format_html(
                '<span class="badge badge-danger">Superuser</span>'
            )
        color = colors.get(obj.user_type, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_user_type_display()
        )
    user_type_badge.short_description = 'Type'
    
    def approval_badge(self, obj):
        colors = {
            'approved': 'success',
            'pending': 'warning',
            'rejected': 'danger',
            'suspended': 'dark',
        }
        color = colors.get(obj.approval_status, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_approval_status_display()
        )
    approval_badge.short_description = 'Status'
    
    def mfa_badge(self, obj):
        if obj.mfa_enabled:
            return format_html('<span class="badge badge-success">✓ Enabled</span>')
        return format_html('<span class="badge badge-danger">✗ Disabled</span>')
    mfa_badge.short_description = 'MFA'
    
    actions = ['approve_users', 'reject_users', 'suspend_users', 'activate_users',
               'reset_mfa', 'force_password_reset']
    
    def approve_users(self, request, queryset):
        count = 0
        for user in queryset:
            if not user.is_approved:
                user.approve_user(request.user)
                count += 1
        self.message_user(request, f'{count} users approved.')
    approve_users.short_description = 'Approve selected users'
    
    def reject_users(self, request, queryset):
        count = queryset.filter(approval_status='pending').update(
            approval_status='rejected',
            is_approved=False
        )
        self.message_user(request, f'{count} users rejected.')
    reject_users.short_description = 'Reject selected users'
    
    def suspend_users(self, request, queryset):
        count = queryset.update(is_active=False, approval_status='suspended')
        self.message_user(request, f'{count} users suspended.')
    suspend_users.short_description = 'Suspend selected users'
    
    def activate_users(self, request, queryset):
        count = queryset.update(is_active=True)
        self.message_user(request, f'{count} users activated.')
    activate_users.short_description = 'Activate selected users'
    
    def reset_mfa(self, request, queryset):
        count = queryset.update(
            mfa_enabled=False,
            mfa_secret='',
            mfa_backup_codes=[]
        )
        self.message_user(request, f'MFA reset for {count} users.')
    reset_mfa.short_description = 'Reset MFA for selected users'
    
    def force_password_reset(self, request, queryset):
        count = queryset.update(
            last_password_change=timezone.now() - timezone.timedelta(days=365)
        )
        self.message_user(request, f'Password reset forced for {count} users.')
    force_password_reset.short_description = 'Force password reset'


@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    """Admin for password history"""
    list_display = ['user', 'created_at']
    list_filter = ['created_at']
    search_fields = ['user__email']
    readonly_fields = ['user', 'password_hash', 'created_at']
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False