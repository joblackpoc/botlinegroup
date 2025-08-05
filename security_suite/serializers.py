# security_suite/serializers.py

from rest_framework import serializers
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.core.validators import validate_email, validate_ipv4_address, validate_ipv6_address
from .models import (
    SecurityAlert, IPBlacklist, SecurityConfiguration,
    SessionMonitor, ThreatIntelligence, SecurityReport,
    SecurityIncident, ComplianceFramework
)
from .utils import mask_email, check_password_strength
from accounts.serializers import UserSerializer
import re


class MaskedEmailField(serializers.Field):
    """Custom field to automatically mask email addresses"""
    
    def to_representation(self, value):
        if value:
            return mask_email(value)
        return None
    
    def to_internal_value(self, data):
        # Validate email when setting
        if data:
            validate_email(data)
        return data


class SecurityAlertSerializer(serializers.ModelSerializer):
    """Enhanced serializer for security alerts with validation"""
    user_email = MaskedEmailField(source='user.email', read_only=True)
    alert_type_display = serializers.CharField(source='get_alert_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    age = serializers.SerializerMethodField()
    risk_score_label = serializers.SerializerMethodField()
    acknowledged_by_email = MaskedEmailField(source='acknowledged_by.email', read_only=True)
    resolved_by_email = MaskedEmailField(source='resolved_by.email', read_only=True)
    
    class Meta:
        model = SecurityAlert
        fields = [
            'id', 'alert_type', 'alert_type_display', 'severity', 'severity_display',
            'status', 'status_display', 'title', 'description', 'details',
            'data_classification', 'user', 'user_email', 'ip_address', 'user_agent',
            'correlation_id', 'parent_alert', 'source_system',
            'created_at', 'updated_at', 'acknowledged_at', 'resolved_at',
            'acknowledged_by', 'acknowledged_by_email', 'resolved_by', 
            'resolved_by_email', 'resolution_notes', 'auto_resolved', 
            'notification_sent', 'escalation_level', 'risk_score', 
            'risk_score_label', 'age'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'acknowledged_at', 'resolved_at',
            'acknowledged_by', 'resolved_by', 'risk_score'
        ]
        extra_kwargs = {
            'user_agent': {'write_only': True},  # Don't expose full user agent
            'resolution_notes': {'write_only': True},  # Sensitive information
        }
    
    def get_age(self, obj):
        """Get age of alert in human-readable format"""
        age = timezone.now() - obj.created_at
        days = age.days
        hours = age.seconds // 3600
        minutes = (age.seconds % 3600) // 60
        
        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def get_risk_score_label(self, obj):
        """Get risk score label"""
        if obj.risk_score >= 80:
            return 'critical'
        elif obj.risk_score >= 60:
            return 'high'
        elif obj.risk_score >= 40:
            return 'medium'
        elif obj.risk_score >= 20:
            return 'low'
        else:
            return 'info'
    
    def validate_details(self, value):
        """Additional validation for details field"""
        if not isinstance(value, dict):
            raise serializers.ValidationError(_("Details must be a dictionary"))
        
        # Limit size to prevent DoS
        import json
        if len(json.dumps(value)) > 10000:  # 10KB limit
            raise serializers.ValidationError(_("Details field is too large"))
        
        return value
    
    def validate_ip_address(self, value):
        """Validate IP address format"""
        if value:
            try:
                # Try both IPv4 and IPv6
                try:
                    validate_ipv4_address(value)
                except:
                    validate_ipv6_address(value)
            except:
                raise serializers.ValidationError(_("Invalid IP address format"))
        return value


class IPBlacklistSerializer(serializers.ModelSerializer):
    """Enhanced serializer for IP blacklist with additional validation"""
    reason_display = serializers.CharField(source='get_reason_display', read_only=True)
    blocked_by_email = MaskedEmailField(source='blocked_by.email', read_only=True)
    unblocked_by_email = MaskedEmailField(source='unblocked_by.email', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    remaining_time = serializers.SerializerMethodField()
    
    class Meta:
        model = IPBlacklist
        fields = [
            'id', 'ip_address', 'ip_range', 'reason', 'reason_display', 
            'description', 'is_active', 'blocked_at', 'expires_at', 
            'blocked_by', 'blocked_by_email', 'unblocked_by', 
            'unblocked_by_email', 'unblocked_at', 'block_count', 
            'last_attempt', 'threat_score', 'country_code', 'asn',
            'auto_blocked', 'whitelist_requested', 'is_expired', 'remaining_time'
        ]
        read_only_fields = [
            'id', 'blocked_at', 'blocked_by', 'unblocked_by', 'unblocked_at',
            'block_count', 'last_attempt', 'threat_score'
        ]
    
    def get_remaining_time(self, obj):
        """Get remaining block time"""
        if not obj.expires_at or not obj.is_active:
            return None
        
        remaining = obj.expires_at - timezone.now()
        if remaining.total_seconds() <= 0:
            return "Expired"
        
        days = remaining.days
        hours = remaining.seconds // 3600
        minutes = (remaining.seconds % 3600) // 60
        
        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
    
    def validate_ip_range(self, value):
        """Validate CIDR notation"""
        if value:
            import ipaddress
            try:
                ipaddress.ip_network(value)
            except ValueError:
                raise serializers.ValidationError(_("Invalid CIDR notation"))
        return value
    
    def validate_expires_at(self, value):
        """Ensure expiration is in the future"""
        if value and value <= timezone.now():
            raise serializers.ValidationError(_("Expiration date must be in the future"))
        return value


class SecurityConfigSerializer(serializers.ModelSerializer):
    """Enhanced serializer for security configuration with comprehensive validation"""
    password_policy_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityConfiguration
        fields = [
            'id', 'name', 'is_active', 'max_login_attempts', 
            'lockout_duration_minutes', 'session_timeout_minutes', 
            'min_password_length', 'require_uppercase', 'require_lowercase', 
            'require_numbers', 'require_special_chars', 'password_expiry_days', 
            'password_history_count', 'mfa_required', 'mfa_grace_period_days',
            'mfa_backup_codes_count', 'mfa_remember_device_days',
            'rate_limit_enabled', 'rate_limit_requests', 
            'rate_limit_period_seconds', 'ip_whitelist_enabled', 'ip_whitelist',
            'security_headers_enabled', 'content_security_policy',
            'strict_transport_security', 'secure_cookie', 'httponly_cookie',
            'samesite_cookie', 'audit_retention_days', 'failed_login_threshold',
            'real_time_monitoring', 'alert_threshold_critical', 
            'alert_threshold_high', 'created_at', 'updated_at', 'updated_by',
            'password_policy_summary'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'updated_by']
    
    def get_password_policy_summary(self, obj):
        """Generate human-readable password policy summary"""
        requirements = []
        
        requirements.append(f"Minimum {obj.min_password_length} characters")
        
        if obj.require_uppercase:
            requirements.append("At least one uppercase letter")
        if obj.require_lowercase:
            requirements.append("At least one lowercase letter")
        if obj.require_numbers:
            requirements.append("At least one number")
        if obj.require_special_chars:
            requirements.append("At least one special character")
        
        return requirements
    
    def validate_min_password_length(self, value):
        if value < 8:
            raise serializers.ValidationError(_("Minimum password length must be at least 8"))
        if value > 128:
            raise serializers.ValidationError(_("Minimum password length cannot exceed 128"))
        return value
    
    def validate_password_history_count(self, value):
        if value < 1:
            raise serializers.ValidationError(_("Password history must track at least 1 password"))
        if value > 24:
            raise serializers.ValidationError(_("Password history cannot exceed 24 passwords"))
        return value
    
    def validate_lockout_duration_minutes(self, value):
        if value < 5:
            raise serializers.ValidationError(_("Lockout duration must be at least 5 minutes"))
        if value > 1440:  # 24 hours
            raise serializers.ValidationError(_("Lockout duration cannot exceed 24 hours"))
        return value
    
    def validate_ip_whitelist(self, value):
        """Validate all IPs in whitelist"""
        if value:
            for ip in value:
                try:
                    validate_ipv4_address(ip)
                except:
                    try:
                        validate_ipv6_address(ip)
                    except:
                        raise serializers.ValidationError(f"Invalid IP address: {ip}")
        return value
    
    def validate(self, data):
        """Cross-field validation"""
        # Ensure at least one password requirement is enabled
        password_reqs = [
            data.get('require_uppercase', self.instance.require_uppercase if self.instance else True),
            data.get('require_lowercase', self.instance.require_lowercase if self.instance else True),
            data.get('require_numbers', self.instance.require_numbers if self.instance else True),
            data.get('require_special_chars', self.instance.require_special_chars if self.instance else True),
        ]
        
        if not any(password_reqs):
            raise serializers.ValidationError(
                _("At least one password requirement must be enabled")
            )
        
        return data


class SessionMonitorSerializer(serializers.ModelSerializer):
    """Enhanced serializer for session monitoring with security features"""
    user_email = MaskedEmailField(source='user.email', read_only=True)
    duration = serializers.SerializerMethodField()
    is_expired = serializers.BooleanField(read_only=True)
    device_type = serializers.SerializerMethodField()
    risk_level = serializers.SerializerMethodField()
    location_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = SessionMonitor
        fields = [
            'id', 'user', 'user_email', 'ip_address', 'user_agent', 
            'device_info', 'device_type', 'country', 'country_code', 
            'city', 'region', 'timezone_name', 'created_at', 'last_activity', 
            'expires_at', 'duration', 'page_views', 'api_calls',
            'is_suspicious', 'risk_score', 'risk_level', 'anomaly_flags',
            'terminated', 'terminated_at', 'terminated_by', 'termination_reason',
            'is_expired', 'location_summary', 'concurrent_sessions'
        ]
        read_only_fields = [
            'id', 'created_at', 'last_activity', 'expires_at',
            'terminated_at', 'terminated_by', 'page_views', 'api_calls',
            'risk_score', 'concurrent_sessions'
        ]
        extra_kwargs = {
            'user_agent': {'write_only': True},  # Don't expose full user agent
            'termination_reason': {'write_only': True},
        }
    
    def get_duration(self, obj):
        """Get session duration"""
        duration = timezone.now() - obj.created_at
        hours = int(duration.total_seconds() // 3600)
        minutes = int((duration.total_seconds() % 3600) // 60)
        return f"{hours}h {minutes}m"
    
    def get_device_type(self, obj):
        """Extract device type from user agent"""
        if not obj.user_agent:
            return 'Unknown'
        
        user_agent = obj.user_agent.lower()
        if 'mobile' in user_agent or 'android' in user_agent:
            return 'Mobile'
        elif 'tablet' in user_agent or 'ipad' in user_agent:
            return 'Tablet'
        else:
            return 'Desktop'
    
    def get_risk_level(self, obj):
        """Convert risk score to level"""
        if obj.risk_score >= 80:
            return 'critical'
        elif obj.risk_score >= 60:
            return 'high'
        elif obj.risk_score >= 40:
            return 'medium'
        elif obj.risk_score >= 20:
            return 'low'
        else:
            return 'normal'
    
    def get_location_summary(self, obj):
        """Get location summary"""
        parts = []
        if obj.city:
            parts.append(obj.city)
        if obj.region and obj.region != obj.city:
            parts.append(obj.region)
        if obj.country:
            parts.append(obj.country)
        
        return ', '.join(parts) if parts else 'Unknown'


class ThreatIntelligenceSerializer(serializers.ModelSerializer):
    """Enhanced serializer for threat intelligence with validation"""
    threat_type_display = serializers.CharField(source='get_threat_type_display', read_only=True)
    threat_level_display = serializers.CharField(source='get_threat_level_display', read_only=True)
    threat_category_display = serializers.CharField(source='get_threat_category_display', read_only=True)
    age = serializers.SerializerMethodField()
    reliability_score = serializers.SerializerMethodField()
    
    class Meta:
        model = ThreatIntelligence
        fields = [
            'id', 'threat_type', 'threat_type_display', 'threat_value',
            'threat_level', 'threat_level_display', 'threat_category',
            'threat_category_display', 'description', 'source', 'source_url',
            'tags', 'is_active', 'first_seen', 'last_seen', 'expires_at',
            'confidence', 'hit_count', 'false_positive_count', 'severity_score',
            'threat_actor', 'campaign', 'port', 'protocol', 'country_code',
            'asn', 'age', 'reliability_score', 'related_indicators', 'iocs'
        ]
        read_only_fields = [
            'id', 'first_seen', 'last_seen', 'hit_count', 
            'false_positive_count', 'severity_score'
        ]
    
    def get_age(self, obj):
        """Get age of threat intel"""
        age = timezone.now() - obj.first_seen
        days = age.days
        if days > 365:
            return f"{days // 365}y"
        elif days > 30:
            return f"{days // 30}mo"
        else:
            return f"{days}d"
    
    def get_reliability_score(self, obj):
        """Calculate reliability based on confidence and false positives"""
        if obj.false_positive_count >= 5:
            return 0
        
        base_score = obj.confidence
        if obj.false_positive_count > 0:
            base_score = base_score * (1 - (obj.false_positive_count * 0.2))
        
        return max(0, min(100, base_score))
    
    def validate_confidence(self, value):
        if not 0 <= value <= 100:
            raise serializers.ValidationError(_("Confidence must be between 0 and 100"))
        return value
    
    def validate_threat_value(self, value):
        """Validate threat value based on threat type"""
        threat_type = self.initial_data.get('threat_type')
        
        if threat_type == 'ip':
            try:
                validate_ipv4_address(value)
            except:
                try:
                    validate_ipv6_address(value)
                except:
                    raise serializers.ValidationError(_("Invalid IP address format"))
        
        elif threat_type == 'email':
            validate_email(value)
        
        elif threat_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            hash_patterns = {
                'hash_md5': r'^[a-fA-F0-9]{32}',
                'hash_sha1': r'^[a-fA-F0-9]{40}',
                'hash_sha256': r'^[a-fA-F0-9]{64}',
            }
            pattern = hash_patterns.get(threat_type)
            if pattern and not re.match(pattern, value):
                raise serializers.ValidationError(f"Invalid {threat_type} format")
        
        return value
    
    def validate_tags(self, value):
        """Limit number of tags"""
        if len(value) > 20:
            raise serializers.ValidationError(_("Maximum 20 tags allowed"))
        return value


class DashboardDataSerializer(serializers.Serializer):
    """Serializer for dashboard data with nested serialization"""
    alerts_summary = serializers.DictField(child=serializers.IntegerField())
    failed_logins = serializers.DictField(child=serializers.IntegerField())
    sessions = serializers.DictField(child=serializers.IntegerField())
    blocked_ips = serializers.DictField(child=serializers.IntegerField())
    users = serializers.DictField(child=serializers.IntegerField())
    recent_alerts = SecurityAlertSerializer(many=True)
    performance = serializers.DictField()
    timeline = serializers.ListField(child=serializers.DictField())


class SecurityMetricsSerializer(serializers.Serializer):
    """Serializer for security metrics"""
    period = serializers.CharField()
    threat_metrics = serializers.DictField(child=serializers.IntegerField())
    auth_metrics = serializers.DictField()
    top_threat_ips = serializers.ListField(
        child=serializers.DictField(
            child=serializers.CharField()
        )
    )
    alert_distribution = serializers.ListField(
        child=serializers.DictField()
    )


class SecurityReportSerializer(serializers.ModelSerializer):
    """Serializer for security reports"""
    requested_by_email = MaskedEmailField(source='requested_by.email', read_only=True)
    report_type_display = serializers.CharField(source='get_report_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = SecurityReport
        fields = [
            'id', 'title', 'report_type', 'report_type_display', 'status',
            'status_display', 'date_range_start', 'date_range_end', 'filters',
            'created_at', 'generated_at', 'expires_at', 'requested_by',
            'requested_by_email', 'file', 'file_size', 'file_format',
            'file_checksum', 'record_count', 'summary', 'error_message',
            'classification', 'access_count', 'last_accessed', 'is_expired'
        ]
        read_only_fields = [
            'id', 'created_at', 'generated_at', 'expires_at', 'file',
            'file_size', 'file_checksum', 'record_count', 'summary',
            'error_message', 'access_count', 'last_accessed'
        ]
    
    def validate_date_range_end(self, value):
        """Ensure end date is after start date"""
        if self.initial_data.get('date_range_start'):
            start = self.initial_data['date_range_start']
            if value < start:
                raise serializers.ValidationError(
                    _("End date must be after start date")
                )
        return value
    
    def validate_filters(self, value):
        """Validate filter structure"""
        if not isinstance(value, dict):
            raise serializers.ValidationError(_("Filters must be a dictionary"))
        
        # Limit size to prevent DoS
        import json
        if len(json.dumps(value)) > 5000:  # 5KB limit
            raise serializers.ValidationError(_("Filters are too large"))
        
        return value


class SecurityIncidentSerializer(serializers.ModelSerializer):
    """Serializer for security incidents"""
    created_by_email = MaskedEmailField(source='created_by.email', read_only=True)
    assigned_to_email = MaskedEmailField(source='assigned_to.email', read_only=True)
    incident_type_display = serializers.CharField(source='get_incident_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = SecurityIncident
        fields = [
            'id', 'incident_id', 'title', 'description', 'incident_type',
            'incident_type_display', 'severity', 'severity_display', 'status',
            'status_display', 'discovered_at', 'occurred_at', 'created_at',
            'updated_at', 'closed_at', 'assigned_to', 'assigned_to_email',
            'created_by', 'created_by_email', 'affected_systems',
            'affected_users_count', 'data_compromised', 'financial_impact',
            'related_alerts', 'resolution_summary', 'lessons_learned',
            'response_team', 'evidence_collected', 'chain_of_custody'
        ]
        read_only_fields = [
            'id', 'incident_id', 'created_at', 'updated_at', 'closed_at',
            'created_by', 'chain_of_custody'
        ]
    
    def validate_affected_systems(self, value):
        """Limit affected systems list"""
        if len(value) > 100:
            raise serializers.ValidationError(
                _("Maximum 100 affected systems allowed")
            )
        return value
    
    def validate_response_team(self, value):
        """Validate response team emails"""
        if len(value) > 50:
            raise serializers.ValidationError(
                _("Maximum 50 response team members allowed")
            )
        
        for email in value:
            validate_email(email)
        
        return value


class ComplianceFrameworkSerializer(serializers.ModelSerializer):
    """Serializer for compliance frameworks"""
    framework_type_display = serializers.CharField(source='get_framework_type_display', read_only=True)
    is_assessment_due = serializers.BooleanField(read_only=True)
    compliance_status = serializers.SerializerMethodField()
    
    class Meta:
        model = ComplianceFramework
        fields = [
            'id', 'name', 'framework_type', 'framework_type_display', 'version',
            'description', 'is_active', 'compliance_percentage', 'last_assessment',
            'next_assessment', 'controls_total', 'controls_implemented',
            'controls_partial', 'controls_not_implemented', 'created_at',
            'updated_at', 'created_by', 'is_assessment_due', 'compliance_status'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'created_by',
            'compliance_percentage'
        ]
    
    def get_compliance_status(self, obj):
        """Get compliance status based on percentage"""
        if obj.compliance_percentage >= 90:
            return 'compliant'
        elif obj.compliance_percentage >= 70:
            return 'partially_compliant'
        else:
            return 'non_compliant'
    
    def validate(self, data):
        """Validate control counts"""
        total = data.get('controls_total', 0)
        implemented = data.get('controls_implemented', 0)
        partial = data.get('controls_partial', 0)
        not_implemented = data.get('controls_not_implemented', 0)
        
        if implemented + partial + not_implemented > total:
            raise serializers.ValidationError(
                _("Sum of control statuses cannot exceed total controls")
            )
        
        return data


class PasswordStrengthSerializer(serializers.Serializer):
    """Serializer for password strength validation"""
    password = serializers.CharField(write_only=True, min_length=1)
    score = serializers.IntegerField(read_only=True)
    strength = serializers.CharField(read_only=True)
    feedback = serializers.ListField(child=serializers.CharField(), read_only=True)
    valid = serializers.BooleanField(read_only=True)
    
    def validate_password(self, value):
        """Check password strength"""
        result = check_password_strength(value)
        
        # Store result for serialization
        self.validated_data.update(result)
        
        if not result['valid']:
            raise serializers.ValidationError(result['feedback'])
        
        return value