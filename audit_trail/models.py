from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from cryptography.fernet import Fernet
import uuid
import json


class AuditLog(models.Model):
    """Comprehensive audit logging"""
    
    ACTION_CHOICES = (
        # Authentication
        ('login', _('User Login')),
        ('logout', _('User Logout')),
        ('login_failed', _('Failed Login')),
        ('password_changed', _('Password Changed')),
        ('password_reset', _('Password Reset')),
        ('mfa_enabled', _('MFA Enabled')),
        ('mfa_disabled', _('MFA Disabled')),
        ('mfa_verified', _('MFA Verified')),
        ('mfa_failed', _('MFA Failed')),
        
        # User Management
        ('user_created', _('User Created')),
        ('user_updated', _('User Updated')),
        ('user_deleted', _('User Deleted')),
        ('user_approved', _('User Approved')),
        ('user_rejected', _('User Rejected')),
        ('user_suspended', _('User Suspended')),
        ('user_activated', _('User Activated')),
        
        # Group Management
        ('group_created', _('Group Created')),
        ('group_updated', _('Group Updated')),
        ('group_deleted', _('Group Deleted')),
        ('group_password_changed', _('Group Password Changed')),
        ('group_member_added', _('Group Member Added')),
        ('group_member_removed', _('Group Member Removed')),
        
        # Bot Operations
        ('command_executed', _('Command Executed')),
        ('command_failed', _('Command Failed')),
        ('message_received', _('Message Received')),
        ('message_sent', _('Message Sent')),
        
        # Security Events
        ('security_alert', _('Security Alert')),
        ('ip_blocked', _('IP Blocked')),
        ('ip_unblocked', _('IP Unblocked')),
        ('session_terminated', _('Session Terminated')),
        ('rate_limit_exceeded', _('Rate Limit Exceeded')),
        ('unauthorized_access', _('Unauthorized Access')),
        
        # Configuration
        ('config_changed', _('Configuration Changed')),
        ('permission_granted', _('Permission Granted')),
        ('permission_revoked', _('Permission Revoked')),
        
        # Data Operations
        ('data_exported', _('Data Exported')),
        ('data_imported', _('Data Imported')),
        ('data_viewed', _('Data Viewed')),
        ('data_modified', _('Data Modified')),
        ('data_deleted', _('Data Deleted')),
    )
    
    SEVERITY_CHOICES = (
        ('info', _('Info')),
        ('warning', _('Warning')),
        ('error', _('Error')),
        ('critical', _('Critical')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Basic information
    action = models.CharField(
        _('action'),
        max_length=50,
        choices=ACTION_CHOICES
    )
    severity = models.CharField(
        _('severity'),
        max_length=20,
        choices=SEVERITY_CHOICES,
        default='info'
    )
    timestamp = models.DateTimeField(_('timestamp'), default=timezone.now, db_index=True)
    
    # Actor information
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    ip_address = models.GenericIPAddressField(_('IP address'), null=True, blank=True)
    user_agent = models.TextField(_('user agent'), blank=True)
    session_key = models.CharField(_('session key'), max_length=255, blank=True)
    
    # Target information (using Generic Foreign Key)
    content_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    object_id = models.CharField(_('object ID'), max_length=255, null=True, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    object_repr = models.CharField(_('object representation'), max_length=255, blank=True)
    
    # Details
    message = models.TextField(_('message'))
    encrypted_details = models.TextField(_('encrypted details'), blank=True)
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    
    # Search optimization
    search_vector = models.TextField(_('search vector'), blank=True)
    
    class Meta:
        verbose_name = _('audit log')
        verbose_name_plural = _('audit logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['action', '-timestamp']),
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['severity', '-timestamp']),
            models.Index(fields=['content_type', 'object_id']),
            models.Index(fields=['ip_address', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.get_action_display()} - {self.timestamp}"
    
    def set_details(self, details):
        """Encrypt and store sensitive details"""
        if details:
            fernet = Fernet(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
            details_json = json.dumps(details)
            self.encrypted_details = fernet.encrypt(details_json.encode()).decode()
    
    def get_details(self):
        """Decrypt and return sensitive details"""
        if self.encrypted_details:
            try:
                fernet = Fernet(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
                decrypted = fernet.decrypt(self.encrypted_details.encode()).decode()
                return json.loads(decrypted)
            except:
                return {}
        return {}
    
    @classmethod
    def log(cls, action, user=None, severity='info', message='', details=None, 
            content_object=None, ip_address=None, user_agent='', session_key='', 
            metadata=None):
        """Create an audit log entry"""
        
        log = cls(
            action=action,
            severity=severity,
            user=user,
            message=message,
            ip_address=ip_address,
            user_agent=user_agent,
            session_key=session_key,
            metadata=metadata or {}
        )
        
        # Set content object if provided
        if content_object:
            log.content_object = content_object
            log.object_repr = str(content_object)
        
        # Encrypt sensitive details
        if details:
            log.set_details(details)
        
        # Generate search vector
        search_parts = [
            action,
            message,
            user.email if user else '',
            log.object_repr,
            ip_address or ''
        ]
        log.search_vector = ' '.join(filter(None, search_parts)).lower()
        
        log.save()
        return log


class DataAccessLog(models.Model):
    """Track sensitive data access"""
    
    ACCESS_TYPE_CHOICES = (
        ('view', _('View')),
        ('export', _('Export')),
        ('download', _('Download')),
        ('print', _('Print')),
        ('share', _('Share')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Access information
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='data_access_logs'
    )
    access_type = models.CharField(
        _('access type'),
        max_length=20,
        choices=ACCESS_TYPE_CHOICES
    )
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True)
    
    # Data information
    data_type = models.CharField(_('data type'), max_length=100)
    data_identifier = models.CharField(_('data identifier'), max_length=255)
    data_classification = models.CharField(
        _('data classification'),
        max_length=50,
        default='internal'
    )
    
    # Context
    purpose = models.TextField(_('purpose'), blank=True)
    ip_address = models.GenericIPAddressField(_('IP address'))
    user_agent = models.TextField(_('user agent'), blank=True)
    
    # Results
    success = models.BooleanField(_('success'), default=True)
    records_accessed = models.IntegerField(_('records accessed'), default=0)
    
    class Meta:
        verbose_name = _('data access log')
        verbose_name_plural = _('data access logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['data_type', '-timestamp']),
            models.Index(fields=['access_type', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.data_type} - {self.access_type}"


class ComplianceLog(models.Model):
    """Track compliance-related activities"""
    
    COMPLIANCE_TYPE_CHOICES = (
        ('gdpr_request', _('GDPR Request')),
        ('data_retention', _('Data Retention')),
        ('audit_review', _('Audit Review')),
        ('policy_update', _('Policy Update')),
        ('security_assessment', _('Security Assessment')),
        ('incident_response', _('Incident Response')),
        ('user_consent', _('User Consent')),
        ('data_deletion', _('Data Deletion')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Compliance information
    compliance_type = models.CharField(
        _('compliance type'),
        max_length=50,
        choices=COMPLIANCE_TYPE_CHOICES
    )
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True)
    
    # Details
    description = models.TextField(_('description'))
    requestor = models.CharField(_('requestor'), max_length=255)
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='compliance_reviews'
    )
    
    # Status
    status = models.CharField(_('status'), max_length=50, default='pending')
    completed_at = models.DateTimeField(_('completed at'), null=True, blank=True)
    
    # Evidence
    evidence = models.JSONField(_('evidence'), default=dict, blank=True)
    attachments = models.JSONField(_('attachments'), default=list, blank=True)
    
    # Results
    outcome = models.TextField(_('outcome'), blank=True)
    recommendations = models.TextField(_('recommendations'), blank=True)
    
    class Meta:
        verbose_name = _('compliance log')
        verbose_name_plural = _('compliance logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['compliance_type', '-timestamp']),
            models.Index(fields=['status', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.get_compliance_type_display()} - {self.timestamp}"


class PerformanceMetric(models.Model):
    """Track system performance metrics"""
    
    METRIC_TYPE_CHOICES = (
        ('response_time', _('Response Time')),
        ('cpu_usage', _('CPU Usage')),
        ('memory_usage', _('Memory Usage')),
        ('database_queries', _('Database Queries')),
        ('cache_hit_rate', _('Cache Hit Rate')),
        ('error_rate', _('Error Rate')),
        ('active_users', _('Active Users')),
        ('api_calls', _('API Calls')),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Metric information
    metric_type = models.CharField(
        _('metric type'),
        max_length=50,
        choices=METRIC_TYPE_CHOICES
    )
    timestamp = models.DateTimeField(_('timestamp'), default=timezone.now)
    
    # Values
    value = models.FloatField(_('value'))
    unit = models.CharField(_('unit'), max_length=20)
    
    # Context
    endpoint = models.CharField(_('endpoint'), max_length=255, blank=True)
    user_count = models.IntegerField(_('user count'), default=0)
    
    # Thresholds
    warning_threshold = models.FloatField(_('warning threshold'), null=True, blank=True)
    critical_threshold = models.FloatField(_('critical threshold'), null=True, blank=True)
    
    # Metadata
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    
    class Meta:
        verbose_name = _('performance metric')
        verbose_name_plural = _('performance metrics')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['metric_type', '-timestamp']),
            models.Index(fields=['endpoint', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.get_metric_type_display()} - {self.value}{self.unit} - {self.timestamp}"
    
    @property
    def is_warning(self):
        """Check if metric exceeds warning threshold"""
        if self.warning_threshold:
            return self.value > self.warning_threshold
        return False
    
    @property
    def is_critical(self):
        """Check if metric exceeds critical threshold"""
        if self.critical_threshold:
            return self.value > self.critical_threshold
        return False
    
class SecurityAlert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(
        max_length=20,
        choices=(
            ('LOW', 'Low'),
            ('MEDIUM', 'Medium'),
            ('HIGH', 'High'),
            ('CRITICAL', 'Critical')
        )
    )
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} - {self.severity}"