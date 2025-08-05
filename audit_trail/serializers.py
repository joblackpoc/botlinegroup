# audit_trail/serializers.py

from rest_framework import serializers
from django.utils import timezone
from .models import AuditLog, DataAccessLog, ComplianceLog, PerformanceMetric


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for audit logs"""
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True, allow_null=True)
    age = serializers.SerializerMethodField()
    details = serializers.SerializerMethodField()
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'action', 'action_display', 'severity', 'severity_display',
            'timestamp', 'user', 'user_email', 'ip_address', 'user_agent',
            'session_key', 'content_type', 'object_id', 'object_repr',
            'message', 'metadata', 'age', 'details'
        ]
        read_only_fields = fields  # All fields are read-only
    
    def get_age(self, obj):
        """Get age of log entry"""
        age = timezone.now() - obj.timestamp
        days = age.days
        hours = age.seconds // 3600
        minutes = (age.seconds % 3600) // 60
        
        if days > 0:
            return f"{days}d {hours}h ago"
        elif hours > 0:
            return f"{hours}h {minutes}m ago"
        else:
            return f"{minutes}m ago"
    
    def get_details(self, obj):
        """Get decrypted details if available"""
        return obj.get_details()


class DataAccessLogSerializer(serializers.ModelSerializer):
    """Serializer for data access logs"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    access_type_display = serializers.CharField(source='get_access_type_display', read_only=True)
    
    class Meta:
        model = DataAccessLog
        fields = [
            'id', 'user', 'user_email', 'access_type', 'access_type_display',
            'timestamp', 'data_type', 'data_identifier', 'data_classification',
            'purpose', 'ip_address', 'user_agent', 'success', 'records_accessed'
        ]
        read_only_fields = fields  # All fields are read-only


class ComplianceLogSerializer(serializers.ModelSerializer):
    """Serializer for compliance logs"""
    compliance_type_display = serializers.CharField(
        source='get_compliance_type_display',
        read_only=True
    )
    reviewer_email = serializers.CharField(
        source='reviewer.email',
        read_only=True,
        allow_null=True
    )
    duration = serializers.SerializerMethodField()
    
    class Meta:
        model = ComplianceLog
        fields = [
            'id', 'compliance_type', 'compliance_type_display', 'timestamp',
            'description', 'requestor', 'reviewer', 'reviewer_email',
            'status', 'completed_at', 'evidence', 'attachments',
            'outcome', 'recommendations', 'duration'
        ]
        read_only_fields = ['timestamp', 'reviewer', 'completed_at']
    
    def get_duration(self, obj):
        """Get duration to complete"""
        if obj.completed_at:
            duration = obj.completed_at - obj.timestamp
            days = duration.days
            hours = duration.seconds // 3600
            return f"{days}d {hours}h"
        return None
    
    def validate_status(self, value):
        """Validate status transitions"""
        if self.instance:
            current_status = self.instance.status
            if current_status == 'completed' and value != 'completed':
                raise serializers.ValidationError(
                    "Cannot change status of completed compliance log"
                )
        return value


class PerformanceMetricSerializer(serializers.ModelSerializer):
    """Serializer for performance metrics"""
    metric_type_display = serializers.CharField(
        source='get_metric_type_display',
        read_only=True
    )
    status = serializers.SerializerMethodField()
    
    class Meta:
        model = PerformanceMetric
        fields = [
            'id', 'metric_type', 'metric_type_display', 'timestamp',
            'value', 'unit', 'endpoint', 'user_count',
            'warning_threshold', 'critical_threshold',
            'metadata', 'status'
        ]
        read_only_fields = fields  # All fields are read-only
    
    def get_status(self, obj):
        """Get metric status"""
        if obj.is_critical:
            return 'critical'
        elif obj.is_warning:
            return 'warning'
        return 'normal'


class AuditSearchSerializer(serializers.Serializer):
    """Serializer for audit log search"""
    actions = serializers.ListField(
        child=serializers.ChoiceField(choices=AuditLog.ACTION_CHOICES),
        required=False
    )
    severities = serializers.ListField(
        child=serializers.ChoiceField(choices=AuditLog.SEVERITY_CHOICES),
        required=False
    )
    users = serializers.ListField(
        child=serializers.UUIDField(),
        required=False
    )
    ip_addresses = serializers.ListField(
        child=serializers.IPAddressField(),
        required=False
    )
    start_date = serializers.DateTimeField(required=False)
    end_date = serializers.DateTimeField(required=False)
    search_text = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, attrs):
        """Validate search parameters"""
        if attrs.get('start_date') and attrs.get('end_date'):
            if attrs['start_date'] > attrs['end_date']:
                raise serializers.ValidationError(
                    "Start date must be before end date"
                )
        return attrs


class MetricsChartSerializer(serializers.Serializer):
    """Serializer for metrics chart data"""
    labels = serializers.ListField(child=serializers.CharField())
    datasets = serializers.ListField(
        child=serializers.DictField()
    )