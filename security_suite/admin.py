from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from .models import (
    SecurityAlert, IPBlacklist, SecurityConfiguration,
    SessionMonitor, ThreatIntelligence
)


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    """Admin for security alerts"""
    list_display = ['title', 'alert_type_badge', 'severity_badge', 'status_badge',
                   'user', 'created_at', 'resolved_at']
    list_filter = ['alert_type', 'severity', 'status', 'created_at', 'resolved_at']
    search_fields = ['title', 'description', 'user__email', 'ip_address']
    readonly_fields = ['created_at', 'updated_at', 'acknowledged_at', 'resolved_at',
                      'acknowledged_by', 'resolved_by']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Alert Information', {
            'fields': ('alert_type', 'severity', 'status', 'title', 'description')
        }),
        ('Related Entities', {
            'fields': ('user', 'ip_address', 'user_agent')
        }),
        ('Details', {
            'fields': ('details',),
            'classes': ('collapse',)
        }),
        ('Response', {
            'fields': ('acknowledged_at', 'acknowledged_by', 'resolved_at',
                      'resolved_by', 'resolution_notes', 'auto_resolved',
                      'notification_sent')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def alert_type_badge(self, obj):
        return format_html(
            '<span class="badge badge-info">{}</span>',
            obj.get_alert_type_display()
        )
    alert_type_badge.short_description = 'Type'
    
    def severity_badge(self, obj):
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'primary',
            'low': 'info',
            'info': 'secondary',
        }
        color = colors.get(obj.severity, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'
    
    def status_badge(self, obj):
        colors = {
            'new': 'danger',
            'acknowledged': 'warning',
            'investigating': 'info',
            'resolved': 'success',
            'false_positive': 'secondary',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    actions = ['acknowledge_alerts', 'resolve_alerts', 'mark_false_positive']
    
    def acknowledge_alerts(self, request, queryset):
        count = 0
        for alert in queryset.filter(status='new'):
            alert.acknowledge(request.user)
            count += 1
        self.message_user(request, f'{count} alerts acknowledged.')
    acknowledge_alerts.short_description = 'Acknowledge selected alerts'
    
    def resolve_alerts(self, request, queryset):
        count = 0
        for alert in queryset.exclude(status='resolved'):
            alert.resolve(request.user, 'Bulk resolved via admin')
            count += 1
        self.message_user(request, f'{count} alerts resolved.')
    resolve_alerts.short_description = 'Resolve selected alerts'
    
    def mark_false_positive(self, request, queryset):
        count = queryset.update(
            status='false_positive',
            resolved_at=timezone.now(),
            resolved_by=request.user
        )
        self.message_user(request, f'{count} alerts marked as false positive.')
    mark_false_positive.short_description = 'Mark as false positive'


@admin.register(IPBlacklist)
class IPBlacklistAdmin(admin.ModelAdmin):
    """Admin for IP blacklist"""
    list_display = ['ip_address', 'reason_badge', 'active_badge', 'blocked_at',
                   'expires_at', 'block_count']
    list_filter = ['reason', 'is_active', 'blocked_at', 'expires_at']
    search_fields = ['ip_address', 'description']
    readonly_fields = ['blocked_at', 'unblocked_at', 'last_attempt']
    
    fieldsets = (
        ('Blacklist Information', {
            'fields': ('ip_address', 'reason', 'description', 'is_active')
        }),
        ('Time Settings', {
            'fields': ('blocked_at', 'expires_at', 'unblocked_at')
        }),
        ('Metadata', {
            'fields': ('blocked_by', 'unblocked_by', 'block_count', 'last_attempt')
        })
    )
    
    def reason_badge(self, obj):
        colors = {
            'brute_force': 'danger',
            'suspicious_activity': 'warning',
            'malicious_requests': 'danger',
            'rate_limit': 'info',
            'manual': 'secondary',
        }
        color = colors.get(obj.reason, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_reason_display()
        )
    reason_badge.short_description = 'Reason'
    
    def active_badge(self, obj):
        if obj.is_expired():
            return format_html('<span class="badge badge-warning">Expired</span>')
        elif obj.is_active:
            return format_html('<span class="badge badge-danger">Active</span>')
        return format_html('<span class="badge badge-success">Inactive</span>')
    active_badge.short_description = 'Status'
    
    actions = ['unblock_ips', 'extend_block', 'make_permanent']
    
    def unblock_ips(self, request, queryset):
        count = 0
        for entry in queryset.filter(is_active=True):
            entry.unblock(request.user)
            count += 1
        self.message_user(request, f'{count} IPs unblocked.')
    unblock_ips.short_description = 'Unblock selected IPs'
    
    def extend_block(self, request, queryset):
        extended_date = timezone.now() + timezone.timedelta(days=30)
        count = queryset.update(expires_at=extended_date)
        self.message_user(request, f'{count} blocks extended by 30 days.')
    extend_block.short_description = 'Extend block by 30 days'
    
    def make_permanent(self, request, queryset):
        count = queryset.update(expires_at=None)
        self.message_user(request, f'{count} blocks made permanent.')
    make_permanent.short_description = 'Make blocks permanent'


@admin.register(SessionMonitor)
class SessionMonitorAdmin(admin.ModelAdmin):
    """Admin for session monitoring"""
    list_display = ['user', 'ip_address', 'location', 'created_at',
                   'last_activity', 'status_badge']
    list_filter = ['is_suspicious', 'terminated', 'created_at', 'last_activity']
    search_fields = ['user__email', 'ip_address', 'session_key']
    readonly_fields = ['session_key', 'created_at', 'last_activity', 'expires_at', 'terminated_at']
    
    def location(self, obj):
        if obj.country and obj.city:
            return f"{obj.city}, {obj.country}"
        return obj.country or "-"
    location.short_description = 'Location'
    
    def status_badge(self, obj):
        if obj.terminated:
            return format_html('<span class="badge badge-danger">Terminated</span>')
        elif obj.is_expired():
            return format_html('<span class="badge badge-warning">Expired</span>')
        elif obj.is_suspicious:
            return format_html('<span class="badge badge-warning">Suspicious</span>')
        return format_html('<span class="badge badge-success">Active</span>')
    status_badge.short_description = 'Status'
    
    actions = ['terminate_sessions', 'mark_suspicious']
    
    def terminate_sessions(self, request, queryset):
        count = 0
        for session in queryset.filter(terminated=False):
            session.terminate(request.user, 'Bulk terminated via admin')
            count += 1
        self.message_user(request, f'{count} sessions terminated.')
    terminate_sessions.short_description = 'Terminate selected sessions'
    
    def mark_suspicious(self, request, queryset):
        count = queryset.update(is_suspicious=True)
        self.message_user(request, f'{count} sessions marked as suspicious.')
    mark_suspicious.short_description = 'Mark as suspicious'