from django.contrib import admin
from django.utils.html import format_html
from .models import AuditLog, DataAccessLog, ComplianceLog, PerformanceMetric
from django.utils import timezone

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin for audit logs"""
    list_display = ['timestamp', 'action_badge', 'severity_badge', 'user',
                   'ip_address', 'message_short']
    list_filter = ['action', 'severity', 'timestamp']
    search_fields = ['message', 'user__email', 'ip_address', 'search_vector']
    readonly_fields = ['timestamp', 'action', 'severity', 'user', 'ip_address',
                      'user_agent', 'session_key', 'content_type', 'object_id',
                      'object_repr', 'message', 'metadata']
    date_hierarchy = 'timestamp'
    
    def action_badge(self, obj):
        return format_html(
            '<span class="badge badge-info">{}</span>',
            obj.get_action_display()
        )
    action_badge.short_description = 'Action'
    
    def severity_badge(self, obj):
        colors = {
            'info': 'info',
            'warning': 'warning',
            'error': 'danger',
            'critical': 'danger',
        }
        color = colors.get(obj.severity, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'
    
    def message_short(self, obj):
        return obj.message[:100] + '...' if len(obj.message) > 100 else obj.message
    message_short.short_description = 'Message'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin.register(DataAccessLog)
class DataAccessLogAdmin(admin.ModelAdmin):
    """Admin for data access logs"""
    list_display = ['timestamp', 'user', 'access_type', 'data_type',
                   'data_identifier', 'success', 'records_accessed']
    list_filter = ['access_type', 'data_type', 'success', 'timestamp']
    search_fields = ['user__email', 'data_identifier', 'purpose']
    readonly_fields = ['timestamp', 'user', 'access_type', 'data_type',
                      'data_identifier', 'data_classification', 'purpose',
                      'ip_address', 'user_agent', 'success', 'records_accessed']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(ComplianceLog)
class ComplianceLogAdmin(admin.ModelAdmin):
    """Admin for compliance logs"""
    list_display = ['timestamp', 'compliance_type_badge', 'status_badge',
                   'requestor', 'reviewer', 'completed_at']
    list_filter = ['compliance_type', 'status', 'timestamp', 'completed_at']
    search_fields = ['description', 'requestor', 'outcome', 'recommendations']
    readonly_fields = ['timestamp']
    
    fieldsets = (
        ('Compliance Information', {
            'fields': ('compliance_type', 'timestamp', 'description', 'requestor')
        }),
        ('Review', {
            'fields': ('reviewer', 'status', 'completed_at')
        }),
        ('Evidence', {
            'fields': ('evidence', 'attachments'),
            'classes': ('collapse',)
        }),
        ('Results', {
            'fields': ('outcome', 'recommendations')
        })
    )
    
    def compliance_type_badge(self, obj):
        return format_html(
            '<span class="badge badge-primary">{}</span>',
            obj.get_compliance_type_display()
        )
    compliance_type_badge.short_description = 'Type'
    
    def status_badge(self, obj):
        colors = {
            'pending': 'warning',
            'completed': 'success',
            'failed': 'danger',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(
            '<span class="badge badge-{}">{}</span>',
            color, obj.status.title()
        )
    status_badge.short_description = 'Status'
    
    actions = ['mark_completed']
    
    def mark_completed(self, request, queryset):
        count = queryset.filter(status='pending').update(
            status='completed',
            completed_at=timezone.now(),
            reviewer=request.user
        )
        self.message_user(request, f'{count} compliance logs marked as completed.')
    mark_completed.short_description = 'Mark as completed'


@admin.register(PerformanceMetric)
class PerformanceMetricAdmin(admin.ModelAdmin):
    """Admin for performance metrics"""
    list_display = ['timestamp', 'metric_type', 'value_display', 'endpoint',
                   'threshold_status']
    list_filter = ['metric_type', 'timestamp']
    search_fields = ['endpoint']
    readonly_fields = ['timestamp', 'metric_type', 'value', 'unit', 'endpoint',
                      'user_count', 'metadata']
    date_hierarchy = 'timestamp'
    
    def value_display(self, obj):
        return f"{obj.value:.2f} {obj.unit}"
    value_display.short_description = 'Value'
    
    def threshold_status(self, obj):
        if obj.is_critical:
            return format_html('<span class="badge badge-danger">Critical</span>')
        elif obj.is_warning:
            return format_html('<span class="badge badge-warning">Warning</span>')
        return format_html('<span class="badge badge-success">Normal</span>')
    threshold_status.short_description = 'Status'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False