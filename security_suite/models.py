from django.db import models, transaction
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
#from django.contrib.postgres.fields import ArrayField
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.core.exceptions import ValidationError
from django.db import transaction
from django.core import validators
import uuid
import json
from datetime import timedelta
import re
import hashlib
import ipaddress
import secrets
from django.utils.html import strip_tags
import bleach

def validate_ip_address(ip):
    # Custom validation logic (e.g., regex check or IP validation)
    if not ip or not ip.strip():
        raise ValidationError("Invalid IP address")

def validate_no_html(value):
    """Enhanced validation that value contains no HTML tags"""
    cleaned = strip_tags(value)
    if cleaned != value:
        raise ValidationError(_('HTML tags are not allowed'))
    
    # Additional check with bleach for safety
    if bleach.clean(value, tags=[], strip=True) != value:
        raise ValidationError(_('HTML content detected'))


def validate_safe_text(value):
    """Enhanced text validation for XSS prevention"""
    # First strip HTML
    validate_no_html(value)
    
    # Check for dangerous patterns
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'data:text/html',
        r'vbscript:',
        r'eval\s*\(',
        r'expression\s*\(',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
            raise ValidationError(_('Potentially dangerous content detected'))


def validate_user_agent(value):
    """Enhanced user agent validation"""
    if not value:
        return
    
    if len(value) > 500:
        raise ValidationError(_('User agent string too long'))
    
    # Basic XSS prevention
    validate_safe_text(value)
    
    # Check for suspicious patterns
    suspicious_patterns = ['<', '>', 'javascript:', 'script', 'eval(']
    value_lower = value.lower()
    for pattern in suspicious_patterns:
        if pattern in value_lower:
            raise ValidationError(_('Invalid user agent format'))


def validate_alert_details(value):
    """Enhanced alert details JSON validation"""
    if not isinstance(value, dict):
        raise ValidationError(_('Details must be a dictionary'))
    
    allowed_keys = {
        'source', 'evidence', 'risk_score', 'affected_resources',
        'correlation_id', 'threat_indicators', 'remediation_steps',
        'false_positive_reason', 'escalation_level', 'metadata',
        'user_count', 'users', 'failed_attempts', 'time_period',
        'unique_ip_count', 'api_calls', 'access_count', 'avg_response_time',
        'threshold', 'error_rate', 'error_count', 'total_requests',
        'session_id', 'reason', 'terminated_by', 'blocked_by'
    }
    
    # Validate keys
    for key in value.keys():
        if key not in allowed_keys:
            raise ValidationError(_(f'Invalid key: {key}'))
    
    # Validate specific fields
    if 'risk_score' in value:
        risk_score = value['risk_score']
        if not isinstance(risk_score, (int, float)) or not 0 <= risk_score <= 100:
            raise ValidationError(_('Risk score must be between 0 and 100'))
    
    # Validate string fields for XSS
    string_fields = ['source', 'evidence', 'false_positive_reason', 'reason']
    for field in string_fields:
        if field in value and isinstance(value[field], str):
            validate_safe_text(value[field])
    
    # Validate list fields
    if 'users' in value and isinstance(value['users'], list):
        if len(value['users']) > 100:  # Limit array size
            raise ValidationError(_('Users list too large'))
        for user in value['users']:
            if not isinstance(user, str):
                raise ValidationError(_('Invalid user format in list'))


def validate_ip_address(value):
    """Enhanced IP address validation with security checks"""
    try:
        ip = ipaddress.ip_address(value)
        
        # Security checks based on configuration
        if hasattr(settings, 'SECURITY_IP_VALIDATION'):
            config = settings.SECURITY_IP_VALIDATION
            
            # Block private IPs if configured
            if config.get('block_private', False) and ip.is_private:
                raise ValidationError(_('Private IP addresses are not allowed'))
            
            # Block loopback
            if ip.is_loopback and not config.get('allow_loopback', False):
                raise ValidationError(_('Loopback addresses are not allowed'))
            
            # Block multicast
            if ip.is_multicast:
                raise ValidationError(_('Multicast addresses are not allowed'))
            
            # Block reserved
            if ip.is_reserved:
                raise ValidationError(_('Reserved addresses are not allowed'))
        else:
            # Default security policy
            if ip.is_loopback or ip.is_multicast or ip.is_reserved:
                raise ValidationError(_('Invalid IP address type'))
                
    except ValueError:
        raise ValidationError(_('Invalid IP address format'))


def sanitize_path(path):
    """Sanitize path for safe logging"""
    if not path:
        return ''
    
    # Remove query parameters that might contain sensitive data
    path = path.split('?')[0]
    
    # Escape HTML entities
    from django.utils.html import escape
    path = escape(path)
    
    # Limit length
    max_length = 255
    if len(path) > max_length:
        path = path[:max_length] + '...'
    
    return path


def mask_email(email):
    """Mask email address for privacy"""
    if not email or '@' not in email:
        return 'unknown'
    
    local, domain = email.split('@', 1)
    if len(local) <= 3:
        masked_local = '*' * len(local)
    else:
        masked_local = local[:2] + '*' * (len(local) - 3) + local[-1]
    
    return f"{masked_local}@{domain}"


def hash_session_key(session_key):
    """Securely hash session keys for storage"""
    if not session_key:
        return None
    
    # Use SHA256 with a salt from settings
    salt = getattr(settings, 'SESSION_KEY_SALT', 'default-salt')
    return hashlib.sha256(f"{salt}:{session_key}".encode()).hexdigest()


class SecurityAlert(models.Model):
    """Enhanced security alerts with improved validation and security"""
    
    SEVERITY_CHOICES = [
        ('critical', _('Critical')),
        ('high', _('High')),
        ('medium', _('Medium')),
        ('low', _('Low')),
        ('info', _('Info')),
    ]
    
    ALERT_TYPE_CHOICES = [
        ('failed_login', _('Failed Login Attempts')),
        ('unauthorized_access', _('Unauthorized Access')),
        ('suspicious_activity', _('Suspicious Activity')),
        ('brute_force', _('Brute Force Attack')),
        ('password_spray', _('Password Spray Attack')),
        ('session_hijack', _('Session Hijacking Attempt')),
        ('privilege_escalation', _('Privilege Escalation')),
        ('data_exfiltration', _('Data Exfiltration Attempt')),
        ('malicious_command', _('Malicious Command Execution')),
        ('rate_limit', _('Rate Limit Exceeded')),
        ('ip_blocked', _('IP Address Blocked')),
        ('mfa_bypass', _('MFA Bypass Attempt')),
        ('account_lockout', _('Account Lockout')),
        ('expired_password', _('Expired Password Usage')),
        ('weak_password', _('Weak Password Detected')),
        ('sql_injection', _('SQL Injection Attempt')),
        ('xss_attempt', _('XSS Attack Attempt')),
        ('csrf_attack', _('CSRF Attack')),
        ('file_upload_threat', _('Malicious File Upload')),
        ('directory_traversal', _('Directory Traversal Attempt')),
    ]
    
    STATUS_CHOICES = [
        ('new', _('New')),
        ('acknowledged', _('Acknowledged')),
        ('investigating', _('Investigating')),
        ('resolved', _('Resolved')),
        ('false_positive', _('False Positive')),
        ('escalated', _('Escalated')),
    ]
    
    CLASSIFICATION_CHOICES = [
        ('public', _('Public')),
        ('internal', _('Internal')),
        ('confidential', _('Confidential')),
        ('restricted', _('Restricted')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    alert_type = models.CharField(
        _('alert type'),
        max_length=50,
        choices=ALERT_TYPE_CHOICES,
        db_index=True
    )
    severity = models.CharField(
        _('severity'),
        max_length=20,
        choices=SEVERITY_CHOICES,
        db_index=True
    )
    status = models.CharField(
        _('status'),
        max_length=20,
        choices=STATUS_CHOICES,
        default='new',
        db_index=True
    )
    
    # Enhanced alert details with validation
    title = models.CharField(
        _('title'), 
        max_length=255, 
        validators=[validate_no_html],
        db_index=True  # Added index for search
    )
    description = models.TextField(_('description'), validators=[validate_safe_text])
    details = models.JSONField(_('details'), default=dict, validators=[validate_alert_details])
    
    # Data classification
    data_classification = models.CharField(
        _('data classification'),
        max_length=20,
        choices=CLASSIFICATION_CHOICES,
        default='internal'
    )
    
    # Related entities with enhanced indexing
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='security_alerts',
        db_index=True
    )
    ip_address = models.GenericIPAddressField(
        _('IP address'), 
        null=True, 
        blank=True,
        validators=[validate_ip_address],
        db_index=True
    )
    user_agent = models.TextField(
        _('user agent'), 
        blank=True, 
        validators=[validate_user_agent]
    )
    
    # Enhanced tracking
    correlation_id = models.CharField(
        _('correlation ID'), 
        max_length=100, 
        blank=True, 
        db_index=True,
        help_text=_('Links related alerts together')
    )
    parent_alert = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='child_alerts'
    )
    source_system = models.CharField(_('source system'), max_length=100, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(_('created at'), auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    acknowledged_at = models.DateTimeField(_('acknowledged at'), null=True, blank=True)
    resolved_at = models.DateTimeField(_('resolved at'), null=True, blank=True)
    
    # Response tracking with audit trail
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_alerts',
        db_index=True  # Added index
    )
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acknowledged_alerts',
        db_index=True
    )
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_alerts',
        db_index=True
    )
    resolution_notes = models.TextField(
        _('resolution notes'), 
        blank=True,
        validators=[validate_safe_text]
    )
    
    # Automation and notification
    auto_resolved = models.BooleanField(_('auto resolved'), default=False)
    notification_sent = models.BooleanField(_('notification sent'), default=False)
    escalation_level = models.PositiveSmallIntegerField(_('escalation level'), default=0)
    
    # Risk scoring
    risk_score = models.FloatField(
        _('risk score'),
        default=0.0,
        help_text=_('Calculated risk score (0-100)')
    )
    
    # Retention policy
    retention_days = models.PositiveIntegerField(_('retention days'), default=365)
    
    class Meta:
        verbose_name = _('security alert')
        verbose_name_plural = _('security alerts')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['severity', '-created_at']),
            models.Index(fields=['alert_type', '-created_at']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['ip_address', '-created_at']),
            models.Index(fields=['correlation_id']),
            models.Index(fields=['status', 'severity']),
            models.Index(fields=['created_at']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['title']),  # Added for search
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(risk_score__gte=0) & models.Q(risk_score__lte=100),
                name='valid_risk_score'
            ),
            models.CheckConstraint(
                check=models.Q(escalation_level__gte=0) & models.Q(escalation_level__lte=10),
                name='valid_escalation_level'
            ),
            # Ensure resolved_at is after acknowledged_at
            models.CheckConstraint(
                check=(
                    models.Q(resolved_at__isnull=True) | 
                    models.Q(acknowledged_at__isnull=True) | 
                    models.Q(resolved_at__gte=models.F('acknowledged_at'))
                ),
                name='resolved_after_acknowledged'
            ),
        ]
    
    def __str__(self):
        return f"{self.get_severity_display()} - {self.title}"
    
    def clean(self):
        """Additional validation"""
        super().clean()
        
        # Validate status transitions
        if self.resolved_at and not self.acknowledged_at:
            raise ValidationError(_('Alert must be acknowledged before resolution'))
        
        if self.resolved_at and self.acknowledged_at:
            if self.resolved_at < self.acknowledged_at:
                raise ValidationError(_('Resolution time cannot be before acknowledgment time'))
    
    @transaction.atomic
    def acknowledge(self, user):
        """Acknowledge the alert with validation and atomic operation"""
        if self.status in ['resolved', 'false_positive']:
            raise ValidationError(_("Cannot acknowledge a resolved or false positive alert"))
        
        self.status = 'acknowledged'
        self.acknowledged_at = timezone.now()
        self.acknowledged_by = user
        self.save(update_fields=['status', 'acknowledged_at', 'acknowledged_by', 'updated_at'])
    
    @transaction.atomic
    def resolve(self, user, notes=''):
        """Resolve the alert with validation and atomic operation"""
        if self.status == 'new':
            raise ValidationError(_("Alert must be acknowledged before resolution"))
        
        if not notes and self.severity in ['critical', 'high']:
            raise ValidationError(_("Resolution notes required for critical/high severity alerts"))
        
        # Validate notes
        if notes:
            validate_safe_text(notes)
        
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.resolution_notes = notes
        self.save(update_fields=['status', 'resolved_at', 'resolved_by', 'resolution_notes', 'updated_at'])
    
    @transaction.atomic
    def escalate(self, user, level=None):
        """Escalate the alert with validation"""
        if level is None:
            level = min(self.escalation_level + 1, 10)  # Max level 10
        else:
            if not 0 <= level <= 10:
                raise ValidationError(_("Escalation level must be between 0 and 10"))
        
        self.escalation_level = level
        self.status = 'escalated'
        self.save(update_fields=['escalation_level', 'status', 'updated_at'])
    
    @property
    def is_expired(self):
        """Check if alert has passed retention period"""
        return timezone.now() > self.created_at + timedelta(days=self.retention_days)
    
    @property
    def age_in_hours(self):
        """Get alert age in hours"""
        return (timezone.now() - self.created_at).total_seconds() / 3600
    
    def calculate_risk_score(self):
        """Calculate risk score based on various factors"""
        score = 0.0
        
        # Base score by severity
        severity_scores = {
            'critical': 100.0,
            'high': 75.0,
            'medium': 50.0,
            'low': 25.0,
            'info': 10.0
        }
        score = severity_scores.get(self.severity, 0.0)
        
        # Adjust based on alert type
        high_risk_types = [
            'brute_force', 'privilege_escalation', 'data_exfiltration',
            'sql_injection', 'malicious_command', 'session_hijack'
        ]
        if self.alert_type in high_risk_types:
            score = min(score * 1.2, 100.0)
        
        # Adjust based on user criticality
        if self.user and hasattr(self.user, 'is_superuser') and self.user.is_superuser:
            score = min(score * 1.3, 100.0)
        
        # Adjust based on classification
        if self.data_classification in ['confidential', 'restricted']:
            score = min(score * 1.1, 100.0)
        
        # Cap at 100
        self.risk_score = min(score, 100.0)
        return self.risk_score


class IPBlacklist(models.Model):
    """Enhanced IP blacklist with improved security and validation"""
    
    REASON_CHOICES = [
        ('brute_force', _('Brute Force Attack')),
        ('suspicious_activity', _('Suspicious Activity')),
        ('malicious_requests', _('Malicious Requests')),
        ('rate_limit', _('Rate Limit Violations')),
        ('manual', _('Manual Block')),
        ('threat_intel', _('Threat Intelligence')),
        ('spam', _('Spam Activity')),
        ('bot_activity', _('Bot Activity')),
        ('vulnerability_scan', _('Vulnerability Scanning')),
        ('ddos', _('DDoS Attack')),
        ('malware', _('Malware Activity')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ip_address = models.GenericIPAddressField(
        _('IP address'), 
        unique=True,
        validators=[validate_ip_address]
    )
    ip_range = models.CharField(
        _('IP range/CIDR'),
        max_length=50,
        blank=True,
        help_text=_('CIDR notation for IP ranges')
    )
    reason = models.CharField(
        _('reason'),
        max_length=50,
        choices=REASON_CHOICES,
        db_index=True
    )
    description = models.TextField(
        _('description'), 
        blank=True,
        validators=[validate_safe_text]
    )
    
    # Block details
    is_active = models.BooleanField(_('active'), default=True, db_index=True)
    blocked_at = models.DateTimeField(_('blocked at'), auto_now_add=True, db_index=True)
    expires_at = models.DateTimeField(_('expires at'), null=True, blank=True, db_index=True)
    
    # Enhanced metadata
    blocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='blocked_ips',
        db_index=True  # Added index
    )
    unblocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='unblocked_ips'
    )
    unblocked_at = models.DateTimeField(_('unblocked at'), null=True, blank=True)
    
    # Statistics and intelligence
    block_count = models.IntegerField(_('block count'), default=1)
    last_attempt = models.DateTimeField(_('last attempt'), null=True, blank=True)
    threat_score = models.FloatField(
        _('threat score'), 
        default=0.0,
        validators=[validators.MinValueValidator(0.0,
                                      message= _('Threat score cannot be negative')
                                      ), 
                    validators.MaxValueValidator(100.0,
                                      message=_('Threat score cannot exceed 100')
                                    )
        ],
        help_text=_('Threat score (0-100)')
    )
    country_code = models.CharField(_('country code'), max_length=2, blank=True, db_index=True)
    asn = models.CharField(_('ASN'), max_length=20, blank=True)
    
    # Automation
    auto_blocked = models.BooleanField(_('auto blocked'), default=False)
    whitelist_requested = models.BooleanField(_('whitelist requested'), default=False)
    
    class Meta:
        verbose_name = _('IP blacklist')
        verbose_name_plural = _('IP blacklist entries')
        ordering = ['-blocked_at']
        indexes = [
            models.Index(fields=['ip_address', 'is_active']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['reason', '-blocked_at']),
            models.Index(fields=['threat_score']),
            models.Index(fields=['country_code']),
            models.Index(fields=['auto_blocked', 'is_active']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(threat_score__gte=0) & models.Q(threat_score__lte=100),
                name='valid_threat_score'
            ),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.get_reason_display()}"
    
    def clean(self):
        """Validate CIDR notation if provided"""
        super().clean()
        
        if self.ip_range:
            try:
                ipaddress.ip_network(self.ip_range)
            except ValueError:
                raise ValidationError(_('Invalid CIDR notation'))
    
    def is_expired(self):
        """Check if block has expired"""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    @transaction.atomic
    def unblock(self, user):
        """Unblock the IP address with atomic operation"""
        self.is_active = False
        self.unblocked_by = user
        self.unblocked_at = timezone.now()
        self.save(update_fields=['is_active', 'unblocked_by', 'unblocked_at'])
    
    def extend_block(self, hours=24):
        """Extend block duration"""
        if hours <= 0:
            raise ValidationError(_("Hours must be positive"))
        
        if self.expires_at:
            self.expires_at += timedelta(hours=hours)
        else:
            self.expires_at = timezone.now() + timedelta(hours=hours)
        self.save(update_fields=['expires_at'])
    
    @transaction.atomic
    def increment_attempts(self):
        """Increment attempt counter atomically"""
        self.block_count = models.F('block_count') + 1
        self.last_attempt = timezone.now()
        self.save(update_fields=['block_count', 'last_attempt'])
        self.refresh_from_db()


class SecurityConfiguration(models.Model):
    """Enhanced security configuration with comprehensive validation"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('configuration name'), max_length=100, unique=True)
    is_active = models.BooleanField(_('active configuration'), default=False)
    
    # Authentication settings with enhanced validation
    max_login_attempts = models.IntegerField(
        _('max login attempts'), 
        default=5,
        validators=[
            validators.MinValueValidator(3),
            validators.MaxValueValidator(10)
        ]
    )
    lockout_duration_minutes = models.IntegerField(
        _('lockout duration (minutes)'), 
        default=30,
        validators=[
            validators.MinValueValidator(5),
            validators.MaxValueValidator(1440)  # Max 24 hours
        ]
    )
    session_timeout_minutes = models.IntegerField(
        _('session timeout (minutes)'), 
        default=30,
        validators=[
            validators.MinValueValidator(5),
            validators.MaxValueValidator(480)  # Max 8 hours
        ]
    )
    
    # Enhanced password policies
    min_password_length = models.IntegerField(
        _('min password length'), 
        default=12,
        validators=[
            validators.MinValueValidator(8),
            validators.MaxValueValidator(128)
        ]
    )
    require_uppercase = models.BooleanField(_('require uppercase'), default=True)
    require_lowercase = models.BooleanField(_('require lowercase'), default=True)
    require_numbers = models.BooleanField(_('require numbers'), default=True)
    require_special_chars = models.BooleanField(_('require special characters'), default=True)
    password_expiry_days = models.IntegerField(
        _('password expiry days'), 
        default=90,
        validators=[
            validators.MinValueValidator(30),
            validators.MaxValueValidator(365)
        ]
    )
    password_history_count = models.IntegerField(
        _('password history count'), 
        default=12,
        validators=[
            validators.MinValueValidator(3),
            validators.MaxValueValidator(24)
        ]
    )
    
    # Enhanced MFA settings
    mfa_required = models.BooleanField(_('MFA required'), default=True)
    mfa_grace_period_days = models.IntegerField(
        _('MFA grace period (days)'), 
        default=7,
        validators=[
            validators.MinValueValidator(0),
            validators.MaxValueValidator(30)
        ]
    )
    mfa_backup_codes_count = models.IntegerField(
        _('MFA backup codes'), 
        default=10,
        validators=[
            validators.MinValueValidator(5),
            validators.MaxValueValidator(20)
        ]
    )
    mfa_remember_device_days = models.IntegerField(
        _('MFA remember device (days)'),
        default=30,
        validators=[
            validators.MinValueValidator(0),
            validators.MaxValueValidator(90)
        ]
    )
    
    # Rate limiting
    rate_limit_enabled = models.BooleanField(_('rate limiting enabled'), default=True)
    rate_limit_requests = models.IntegerField(
        _('rate limit requests'), 
        default=100,
        validators=[
            validators.MinValueValidator(10),
            validators.MaxValueValidator(1000)
        ]
    )
    rate_limit_period_seconds = models.IntegerField(
        _('rate limit period (seconds)'), 
        default=3600,
        validators=[
            validators.MinValueValidator(60),
            validators.MaxValueValidator(86400)  # Max 24 hours
        ]
    )
    
    # IP restrictions
    ip_whitelist_enabled = models.BooleanField(_('IP whitelist enabled'), default=False)
    # ip_whitelist = ArrayField(
    #     models.GenericIPAddressField(),
    #     blank=True,
    #     default=list,
    #     help_text=_('List of whitelisted IP addresses'),
    #     validators=[lambda x: len(x) <= 1000]  # Limit array size
    # )
    ip_whitelist = models.JSONField(default=list, validators=[validate_ip_address])
    # Security headers
    security_headers_enabled = models.BooleanField(_('security headers enabled'), default=True)
    content_security_policy = models.TextField(
        _('Content Security Policy'),
        blank=True,
        default="default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
        validators=[validate_safe_text]
    )
    strict_transport_security = models.CharField(
        _('Strict-Transport-Security'),
        max_length=200,
        default='max-age=31536000; includeSubDomains',
        validators=[validate_no_html]
    )
    
    # Audit settings
    audit_retention_days = models.IntegerField(
        _('audit retention days'), 
        default=90,
        validators=[
            validators.MinValueValidator(30),
            validators.MaxValueValidator(730)  # Max 2 years
        ]
    )
    failed_login_threshold = models.IntegerField(
        _('failed login threshold'), 
        default=10,
        validators=[
            validators.MinValueValidator(5),
            validators.MaxValueValidator(50)
        ]
    )
    
    # Monitoring
    real_time_monitoring = models.BooleanField(_('real-time monitoring'), default=True)
    alert_threshold_critical = models.IntegerField(
        _('critical alert threshold'), 
        default=1,
        validators=[validators.MinValueValidator(1)]
    )
    alert_threshold_high = models.IntegerField(
        _('high alert threshold'), 
        default=5,
        validators=[validators.MinValueValidator(1)]
    )
    
    # Session security
    secure_cookie = models.BooleanField(_('secure cookie'), default=True)
    httponly_cookie = models.BooleanField(_('httponly cookie'), default=True)
    samesite_cookie = models.CharField(
        _('samesite cookie'),
        max_length=10,
        choices=[('Strict', 'Strict'), ('Lax', 'Lax'), ('None', 'None')],
        default='Strict'
    )
    
    # Timestamps
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_index=True
    )
    
    class Meta:
        verbose_name = _('security configuration')
        verbose_name_plural = _('security configurations')
        constraints = [
            models.UniqueConstraint(
                fields=['is_active'],
                condition=models.Q(is_active=True),
                name='single_active_config'
            )
        ]
    
    def __str__(self):
        return f"{self.name} {'(Active)' if self.is_active else ''}"
    
    
    def clean(self):
        """Validate configuration logic"""
        super().clean()
        
        # Ensure at least one password requirement
        if not any([self.require_uppercase, self.require_lowercase, 
                   self.require_numbers, self.require_special_chars]):
            raise ValidationError(_('At least one password requirement must be enabled'))
        
        # Validate IP whitelist
        if self.ip_whitelist:
            for ip in self.ip_whitelist:
                validate_ip_address(ip)
    
    @classmethod
    @transaction.atomic
    def get_active_config(cls):
        """Get active configuration or create default with atomic operation"""
        try:
            return cls.objects.select_for_update().get(is_active=True)
        except cls.DoesNotExist:
            # Create default configuration
            config = cls.objects.create(
                name='default',
                is_active=True,
                max_login_attempts=getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5),
                lockout_duration_minutes=getattr(settings, 'LOCKOUT_DURATION_MINUTES', 30),
                session_timeout_minutes=getattr(settings, 'SESSION_TIMEOUT_MINUTES', 30),
                password_history_count=getattr(settings, 'PASSWORD_HISTORY_COUNT', 12),
                audit_retention_days=getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 90),
            )
            return config
    
    @transaction.atomic
    def activate(self):
        """Activate this configuration (deactivate others) atomically"""
        self.__class__.objects.update(is_active=False)
        self.is_active = True
        self.save(update_fields=['is_active', 'updated_at'])


class SessionMonitor(models.Model):
    """Enhanced session monitoring with improved security"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='monitored_sessions',
        db_index=True
    )
    
    # Secure session storage
    session_key_hash = models.CharField(
        _('session key hash'), 
        max_length=64,  # SHA256 hash length
        unique=True, 
        db_index=True,
        help_text=_('Hashed session key for secure storage')
    )
    
    # Session details
    ip_address = models.GenericIPAddressField(
        _('IP address'),
        validators=[validate_ip_address],
        db_index=True
    )
    user_agent = models.TextField(_('user agent'), validators=[validate_user_agent])
    device_info = models.JSONField(_('device info'), default=dict, blank=True)
    
    # Enhanced location tracking
    country = models.CharField(_('country'), max_length=100, blank=True)
    country_code = models.CharField(_('country code'), max_length=2, blank=True, db_index=True)
    city = models.CharField(_('city'), max_length=100, blank=True)
    region = models.CharField(_('region'), max_length=100, blank=True)
    timezone_name = models.CharField(_('timezone'), max_length=50, blank=True)
    
    # Activity tracking
    created_at = models.DateTimeField(_('created at'), auto_now_add=True, db_index=True)
    last_activity = models.DateTimeField(_('last activity'), auto_now=True, db_index=True)
    expires_at = models.DateTimeField(_('expires at'), db_index=True)
    page_views = models.PositiveIntegerField(_('page views'), default=0)
    api_calls = models.PositiveIntegerField(_('API calls'), default=0)
    is_active = models.BooleanField(_('active'), default=True, db_index=True)
    # Security analytics
    is_suspicious = models.BooleanField(_('suspicious'), default=False, db_index=True)
    risk_score = models.FloatField(
        _('risk score'), 
        default=0.0,
        validators=[validators.MinValueValidator(0), validators.MaxValueValidator(100)]
    )
    # anomaly_flags = ArrayField(
    #     models.CharField(max_length=50),
    #     blank=True,
    #     default=list,
    #     help_text=_('List of detected anomalies')
    # )
    anomaly_flags = models.JSONField(
        _('anomaly flags'),
        default=list,
        blank=True,
        help_text=_('List of detected anomalies'),
        validators=[validate_safe_text]
    )
    # Termination tracking
    terminated = models.BooleanField(_('terminated'), default=False, db_index=True)
    terminated_at = models.DateTimeField(_('terminated at'), null=True, blank=True)
    terminated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='terminated_sessions'
    )
    termination_reason = models.TextField(
        _('termination reason'), 
        blank=True,
        validators=[validate_safe_text]
    )
    
    # Concurrent sessions
    concurrent_sessions = models.PositiveIntegerField(_('concurrent sessions'), default=1)
    
    # Security tokens
    csrf_token_hash = models.CharField(
        _('CSRF token hash'),
        max_length=64,
        blank=True,
        help_text=_('Hash of CSRF token for additional validation')
    )
    
    class Meta:
        verbose_name = _('session monitor')
        verbose_name_plural = _('session monitors')
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', '-last_activity']),
            models.Index(fields=['session_key_hash']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['is_suspicious', '-created_at']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['country_code']),
            models.Index(fields=['terminated', 'expires_at']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(risk_score__gte=0) & models.Q(risk_score__lte=100),
                name='session_valid_risk_score'
            ),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.user.username} - {self.ip_address}"
    
    def save(self, *args, **kwargs):
        """Override save to handle session key hashing"""
        # Note: session_key should be passed via a method, not saved directly
        if hasattr(self, '_session_key'):
            self.session_key_hash = hash_session_key(self._session_key)
            delattr(self, '_session_key')
        super().save(*args, **kwargs)
    
    def set_session_key(self, session_key):
        """Set session key (will be hashed on save)"""
        self._session_key = session_key
    
    def is_expired(self):
        """Check if session has expired"""
        return timezone.now() > self.expires_at
    
    @transaction.atomic
    def terminate(self, terminated_by, reason=''):
        """Terminate the session atomically"""
        if reason:
            validate_safe_text(reason)
        
        self.terminated = True
        self.terminated_at = timezone.now()
        self.terminated_by = terminated_by
        self.termination_reason = reason
        self.save(update_fields=['terminated', 'terminated_at', 'terminated_by', 'termination_reason'])
    
    @transaction.atomic
    def update_activity(self, activity_type='page_view'):
        """Update activity metrics atomically"""
        self.last_activity = timezone.now()
        
        if activity_type == 'page_view':
            self.page_views = models.F('page_views') + 1
        elif activity_type == 'api_call':
            self.api_calls = models.F('api_calls') + 1
        
        self.save(update_fields=['last_activity', 'page_views', 'api_calls'])
        self.refresh_from_db()
    
    def calculate_risk_score(self):
        """Calculate session risk score with enhanced detection"""
        score = 0.0
        
        # Check for multiple IPs for same user
        recent_sessions = SessionMonitor.objects.filter(
            user=self.user,
            created_at__gte=timezone.now() - timedelta(hours=1),
            terminated=False
        ).values('ip_address').distinct().count()
        
        if recent_sessions > 2:
            score += min(recent_sessions * 10, 30.0)
        
        # Check for unusual hours (based on user's timezone if available)
        current_hour = timezone.now().hour
        if current_hour < 6 or current_hour > 22:
            score += 15.0
        
        # Check for high activity volume
        if self.page_views > 100:
            score += min(self.page_views / 10, 20.0)
        if self.api_calls > 500:
            score += min(self.api_calls / 50, 20.0)
        
        # Check location anomalies
        if self.country_code and hasattr(self.user, 'last_login_country'):
            if self.country_code != self.user.last_login_country:
                score += 25.0
        
        # Check for suspicious user agent
        suspicious_agents = ['bot', 'crawler', 'spider', 'scraper']
        if self.user_agent:
            ua_lower = self.user_agent.lower()
            if any(agent in ua_lower for agent in suspicious_agents):
                score += 20.0
        
        # Check anomaly flags
        score += len(self.anomaly_flags) * 5.0
        
        self.risk_score = min(score, 100.0)
        return self.risk_score
    
    def add_anomaly_flag(self, flag):
        """Add anomaly flag with validation"""
        valid_flags = [
            'multiple_ips', 'unusual_hours', 'high_volume', 'location_change',
            'suspicious_agent', 'rapid_requests', 'failed_auth', 'privilege_escalation'
        ]
        
        if flag not in valid_flags:
            raise ValidationError(f"Invalid anomaly flag: {flag}")
        
        if flag not in self.anomaly_flags:
            self.anomaly_flags.append(flag)
            self.is_suspicious = True
            self.save(update_fields=['anomaly_flags', 'is_suspicious'])


class ThreatIntelligence(models.Model):
    """Enhanced threat intelligence with comprehensive tracking"""
    
    THREAT_TYPE_CHOICES = [
        ('ip', _('IP Address')),
        ('domain', _('Domain')),
        ('url', _('URL')),
        ('email', _('Email')),
        ('hash_md5', _('MD5 Hash')),
        ('hash_sha1', _('SHA1 Hash')),
        ('hash_sha256', _('SHA256 Hash')),
        ('pattern', _('Pattern/Signature')),
        ('user_agent', _('User Agent')),
        ('certificate', _('Certificate')),
        ('file_hash', _('File Hash')),
        ('registry_key', _('Registry Key')),
    ]
    
    THREAT_LEVEL_CHOICES = [
        ('critical', _('Critical')),
        ('high', _('High')),
        ('medium', _('Medium')),
        ('low', _('Low')),
        ('info', _('Informational')),
    ]
    
    THREAT_CATEGORY_CHOICES = [
        ('malware', _('Malware')),
        ('phishing', _('Phishing')),
        ('spam', _('Spam')),
        ('botnet', _('Botnet')),
        ('apt', _('Advanced Persistent Threat')),
        ('ransomware', _('Ransomware')),
        ('trojan', _('Trojan')),
        ('vulnerability', _('Vulnerability')),
        ('ddos', _('DDoS')),
        ('scanner', _('Vulnerability Scanner')),
        ('c2', _('Command & Control')),
        ('exploit_kit', _('Exploit Kit')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    threat_type = models.CharField(
        _('threat type'),
        max_length=20,
        choices=THREAT_TYPE_CHOICES,
        db_index=True
    )
    threat_value = models.CharField(
        _('threat value'), 
        max_length=512, 
        db_index=True,
        validators=[validate_safe_text]
    )
    threat_value_hash = models.CharField(
        _('threat value hash'),
        max_length=64,
        blank=True,
        db_index=True,
        help_text=_('SHA256 hash of threat value for indexing')
    )
    threat_level = models.CharField(
        _('threat level'),
        max_length=20,
        choices=THREAT_LEVEL_CHOICES,
        db_index=True
    )
    threat_category = models.CharField(
        _('threat category'),
        max_length=20,
        choices=THREAT_CATEGORY_CHOICES,
        blank=True,
        db_index=True
    )
    
    # Threat details
    description = models.TextField(
        _('description'),
        validators=[validate_safe_text]
    )
    source = models.CharField(_('source'), max_length=100, db_index=True)
    source_url = models.URLField(_('source URL'), blank=True)
    # tags = ArrayField(
    #     models.CharField(max_length=50),
    #     blank=True,
    #     default=list,
    #     validators=[lambda x: len(x) <= 50]  # Limit tags
    # )
    tags = models.JSONField(
        _('Tags'),
        default=list,
        blank=True,
        help_text=_('List of tags for categorization'),
        validators=[validate_safe_text]
    )
    # Status and lifecycle
    is_active = models.BooleanField(_('active'), default=True, db_index=True)
    first_seen = models.DateTimeField(_('first seen'), auto_now_add=True)
    last_seen = models.DateTimeField(_('last seen'), auto_now=True, db_index=True)
    expires_at = models.DateTimeField(_('expires at'), null=True, blank=True, db_index=True)
    
    # Intelligence metadata
    confidence = models.IntegerField(
        _('confidence'),
        default=100,
        validators=[validators.MinValueValidator(0), validators.MaxValueValidator(100)]
    )
    hit_count = models.IntegerField(_('hit count'), default=0, db_index=True)
    false_positive_count = models.IntegerField(_('false positive count'), default=0)
    severity_score = models.FloatField(
        _('severity score'), 
        default=0.0,
        validators=[validators.MinValueValidator(0), validators.MaxValueValidator(100)]
    )
    
    # Attribution
    threat_actor = models.CharField(
        _('threat actor'), 
        max_length=100, 
        blank=True,
        validators=[validate_no_html]
    )
    campaign = models.CharField(
        _('campaign'), 
        max_length=100, 
        blank=True,
        validators=[validate_no_html]
    )
    
    # Technical details
    port = models.PositiveIntegerField(
        _('port'), 
        null=True, 
        blank=True,
        validators=[validators.MaxValueValidator(65535)]
    )
    protocol = models.CharField(_('protocol'), max_length=10, blank=True)
    country_code = models.CharField(_('country code'), max_length=2, blank=True, db_index=True)
    asn = models.CharField(_('ASN'), max_length=20, blank=True)
    
    # Additional intelligence
    # related_indicators = ArrayField(
    #     models.CharField(max_length=512),
    #     blank=True,
    #     default=list,
    #     help_text=_('Related threat indicators')
    # )
    related_indicators = models.JSONField(
        _('Related Indicators'),
        default=list,
        blank=True,
        help_text=_('Related threat indicators')
    )
    iocs = models.JSONField(
        _('Indicators of Compromise'),
        default=dict,
        blank=True,
        help_text=_('Structured IOC data')
    )
    
    class Meta:
        verbose_name = _('threat intelligence')
        verbose_name_plural = _('threat intelligence entries')
        unique_together = [['threat_type', 'threat_value_hash']]
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['threat_type', 'threat_value_hash']),
            models.Index(fields=['is_active', '-last_seen']),
            models.Index(fields=['threat_level', '-last_seen']),
            models.Index(fields=['source', '-last_seen']),
            models.Index(fields=['confidence', '-last_seen']),
            models.Index(fields=['threat_category']),
            models.Index(fields=['country_code']),
            models.Index(fields=['hit_count']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(confidence__gte=0) & models.Q(confidence__lte=100),
                name='valid_confidence'
            ),
            models.CheckConstraint(
                check=models.Q(severity_score__gte=0) & models.Q(severity_score__lte=100),
                name='valid_severity_score'
            ),
        ]
    
    def save(self, *args, **kwargs):
        # Generate hash for indexing
        if not self.threat_value_hash:
            self.threat_value_hash = hashlib.sha256(
                self.threat_value.encode('utf-8')
            ).hexdigest()
        
        # Validate threat value based on type
        self._validate_threat_value()
        
        super().save(*args, **kwargs)
    
    def _validate_threat_value(self):
        """Validate threat value based on type"""
        if self.threat_type == 'ip':
            validate_ip_address(self.threat_value)
        elif self.threat_type == 'email':
            from django.core.validators import validate_email
            validate_email(self.threat_value)
        elif self.threat_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            # Validate hash format
            hash_lengths = {
                'hash_md5': 32,
                'hash_sha1': 40,
                'hash_sha256': 64
            }
            expected_length = hash_lengths[self.threat_type]
            if not re.match(f'^[a-fA-F0-9]{{{expected_length}}} , self.threat_value'):
                raise ValidationError(f'Invalid {self.threat_type} format')
    
    def __str__(self):
        return f"{self.get_threat_type_display()} - {self.threat_value[:50]}"
    
    @transaction.atomic
    def record_hit(self):
        """Record a hit on this threat indicator atomically"""
        self.hit_count = models.F('hit_count') + 1
        self.last_seen = timezone.now()
        self.save(update_fields=['hit_count', 'last_seen'])
        self.refresh_from_db()
    
    @transaction.atomic
    def mark_false_positive(self):
        """Mark as false positive with automatic deactivation"""
        self.false_positive_count = models.F('false_positive_count') + 1
        self.save(update_fields=['false_positive_count'])
        self.refresh_from_db()
        
        # Deactivate if too many false positives
        if self.false_positive_count >= 5:
            self.is_active = False
            self.save(update_fields=['is_active'])
    
    def is_expired(self):
        """Check if threat intelligence has expired"""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def calculate_severity_score(self):
        """Calculate severity score based on multiple factors"""
        score = 0.0
        
        # Base score by threat level
        level_scores = {
            'critical': 100.0,
            'high': 75.0,
            'medium': 50.0,
            'low': 25.0,
            'info': 10.0
        }
        score = level_scores.get(self.threat_level, 0.0)
        
        # Adjust by category
        high_risk_categories = ['ransomware', 'apt', 'c2', 'exploit_kit']
        if self.threat_category in high_risk_categories:
            score = min(score * 1.2, 100.0)
        
        # Adjust by confidence
        score = score * (self.confidence / 100.0)
        
        # Adjust by hit count (more hits = higher severity)
        if self.hit_count > 10:
            score = min(score * 1.1, 100.0)
        
        self.severity_score = score
        return self.severity_score


class SecurityReport(models.Model):
    """Enhanced security reports with comprehensive tracking"""
    
    REPORT_TYPE_CHOICES = [
        ('summary', _('Security Summary')),
        ('threat_analysis', _('Threat Analysis')),
        ('incident_report', _('Incident Report')),
        ('audit_log', _('Audit Log')),
        ('compliance', _('Compliance Report')),
        ('vulnerability', _('Vulnerability Assessment')),
        ('risk_assessment', _('Risk Assessment')),
        ('forensic', _('Forensic Analysis')),
        ('executive', _('Executive Summary')),
    ]
    
    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('generating', _('Generating')),
        ('completed', _('Completed')),
        ('failed', _('Failed')),
        ('expired', _('Expired')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(
        _('title'), 
        max_length=200, 
        validators=[validate_no_html]
    )
    report_type = models.CharField(
        _('report type'),
        max_length=50,
        choices=REPORT_TYPE_CHOICES,
        db_index=True
    )
    status = models.CharField(
        _('status'),
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        db_index=True
    )
    
    # Report parameters
    date_range_start = models.DateTimeField(_('date range start'))
    date_range_end = models.DateTimeField(_('date range end'))
    filters = models.JSONField(_('filters'), default=dict, blank=True)
    
    # Generation details
    created_at = models.DateTimeField(_('created at'), auto_now_add=True, db_index=True)
    generated_at = models.DateTimeField(_('generated at'), null=True, blank=True)
    expires_at = models.DateTimeField(_('expires at'), null=True, blank=True, db_index=True)
    
    # User tracking
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='requested_reports',
        db_index=True
    )
    
    # File storage
    file = models.FileField(
        upload_to='security_reports/%Y/%m/',
        null=True,
        blank=True,
        max_length=500
    )
    file_size = models.PositiveIntegerField(_('file size'), null=True, blank=True)
    file_format = models.CharField(
        _('file format'), 
        max_length=10, 
        default='pdf',
        choices=[('pdf', 'PDF'), ('csv', 'CSV'), ('json', 'JSON'), ('xlsx', 'Excel')]
    )
    file_checksum = models.CharField(
        _('file checksum'),
        max_length=64,
        blank=True,
        help_text=_('SHA256 checksum of generated file')
    )
    
    # Report metadata
    record_count = models.PositiveIntegerField(_('record count'), default=0)
    summary = models.JSONField(_('summary'), default=dict, blank=True)
    error_message = models.TextField(
        _('error message'), 
        blank=True,
        validators=[validate_safe_text]
    )
    
    # Security classification
    classification = models.CharField(
        _('classification'),
        max_length=20,
        choices=SecurityAlert.CLASSIFICATION_CHOICES,
        default='internal'
    )
    
    # Access control
    access_count = models.PositiveIntegerField(_('access count'), default=0)
    last_accessed = models.DateTimeField(_('last accessed'), null=True, blank=True)
    
    class Meta:
        verbose_name = _('security report')
        verbose_name_plural = _('security reports')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['report_type', '-created_at']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['requested_by', '-created_at']),
            models.Index(fields=['expires_at']),
            models.Index(fields=['classification']),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(date_range_end__gte=models.F('date_range_start')),
                name='valid_date_range'
            ),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.get_report_type_display()}"
    
    def clean(self):
        """Validate report parameters"""
        super().clean()
        
        # Validate date range
        if self.date_range_end < self.date_range_start:
            raise ValidationError(_('End date must be after start date'))
        
        # Limit date range to prevent DoS
        max_days = 365
        if (self.date_range_end - self.date_range_start).days > max_days:
            raise ValidationError(f'Date range cannot exceed {max_days} days')
    
    @transaction.atomic
    def mark_completed(self, file_path=None, summary_data=None):
        """Mark report as completed"""
        self.status = 'completed'
        self.generated_at = timezone.now()
        
        if file_path:
            self.file = file_path
            # Calculate file checksum
            import hashlib
            with open(file_path, 'rb') as f:
                self.file_checksum = hashlib.sha256(f.read()).hexdigest()
        
        if summary_data:
            self.summary = summary_data
        
        # Set expiration (30 days default)
        self.expires_at = timezone.now() + timedelta(days=30)
        self.save()
    
    def mark_failed(self, error_message):
        """Mark report as failed"""
        validate_safe_text(error_message)
        self.status = 'failed'
        self.error_message = error_message
        self.save()
    
    @property
    def is_expired(self):
        """Check if report has expired"""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def record_access(self):
        """Record report access"""
        self.access_count = models.F('access_count') + 1
        self.last_accessed = timezone.now()
        self.save(update_fields=['access_count', 'last_accessed'])


class SecurityIncident(models.Model):
    """Enhanced security incident management with atomic operations"""
    
    INCIDENT_TYPE_CHOICES = [
        ('data_breach', _('Data Breach')),
        ('malware_infection', _('Malware Infection')),
        ('unauthorized_access', _('Unauthorized Access')),
        ('ddos_attack', _('DDoS Attack')),
        ('phishing_attack', _('Phishing Attack')),
        ('insider_threat', _('Insider Threat')),
        ('system_compromise', _('System Compromise')),
        ('social_engineering', _('Social Engineering')),
        ('physical_security', _('Physical Security')),
        ('supply_chain', _('Supply Chain Attack')),
        ('zero_day', _('Zero Day Exploit')),
        ('other', _('Other')),
    ]
    
    SEVERITY_CHOICES = SecurityAlert.SEVERITY_CHOICES
    
    STATUS_CHOICES = [
        ('new', _('New')),
        ('investigating', _('Investigating')),
        ('contained', _('Contained')),
        ('eradicated', _('Eradicated')),
        ('recovered', _('Recovered')),
        ('lessons_learned', _('Lessons Learned')),
        ('closed', _('Closed')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident_id = models.CharField(
        _('incident ID'), 
        max_length=20, 
        unique=True, 
        db_index=True
    )
    
    # Basic incident details
    title = models.CharField(
        _('title'), 
        max_length=255, 
        validators=[validate_no_html]
    )
    description = models.TextField(
        _('description'), 
        validators=[validate_safe_text]
    )
    incident_type = models.CharField(
        _('incident type'),
        max_length=30,
        choices=INCIDENT_TYPE_CHOICES,
        db_index=True
    )
    severity = models.CharField(
        _('severity'),
        max_length=20,
        choices=SEVERITY_CHOICES,
        db_index=True
    )
    status = models.CharField(
        _('status'),
        max_length=20,
        choices=STATUS_CHOICES,
        default='new',
        db_index=True
    )
    
    # Timeline
    discovered_at = models.DateTimeField(_('discovered at'))
    occurred_at = models.DateTimeField(_('occurred at'), null=True, blank=True)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    closed_at = models.DateTimeField(_('closed at'), null=True, blank=True)
    
    # Assignment
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_incidents',
        db_index=True
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='created_incidents',
        db_index=True
    )
    
    # Impact assessment
    # affected_systems = ArrayField(
    #     models.CharField(max_length=100),
    #     blank=True,
    #     default=list,
    #     validators=[lambda x: len(x) <= 100]  # Limit array size
    # )
    affected_systems = models.JSONField(
        _('affected systems'),
        default=list,
        blank=True,
        help_text=_('List of affected systems or components'),
        validators=[validate_safe_text]
    )
    affected_users_count = models.PositiveIntegerField(
        _('affected users count'), 
        default=0,
        validators=[validators.MaxValueValidator(1000000)]
    )
    data_compromised = models.BooleanField(_('data compromised'), default=False)
    financial_impact = models.DecimalField(
        _('financial impact'),
        max_digits=12,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[validators.MinValueValidator(0)]
    )
    
    # Related alerts
    related_alerts = models.ManyToManyField(
        SecurityAlert,
        blank=True,
        related_name='incidents'
    )
    
    # Resolution
    resolution_summary = models.TextField(
        _('resolution summary'), 
        blank=True,
        validators=[validate_safe_text]
    )
    lessons_learned = models.TextField(
        _('lessons learned'), 
        blank=True,
        validators=[validate_safe_text]
    )
    
    # Incident response team
    # response_team = ArrayField(
    #     models.EmailField(),
    #     blank=True,
    #     default=list,
    #     help_text=_('Email addresses of response team members')
    # )
    response_team = models.JSONField(
        _('response team'),
        default=list,
        blank=True,
        help_text=_('Email addresses for incident response team members'),
        validators=[validate_safe_text]
    )
    # Evidence and artifacts
    evidence_collected = models.BooleanField(_('evidence collected'), default=False)
    chain_of_custody = models.JSONField(
        _('chain of custody'),
        default=dict,
        blank=True,
        help_text=_('Evidence chain of custody log')
    )
    
    class Meta:
        verbose_name = _('security incident')
        verbose_name_plural = _('security incidents')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['incident_id']),
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['severity', '-created_at']),
            models.Index(fields=['incident_type', '-created_at']),
            models.Index(fields=['assigned_to', '-created_at']),
            models.Index(fields=['discovered_at']),
        ]
    
    @transaction.atomic
    def save(self, *args, **kwargs):
        if not self.incident_id:
            # Generate incident ID with atomic operation
            year = timezone.now().year
            
            # Use select_for_update to prevent race conditions
            last_incident = SecurityIncident.objects.select_for_update().filter(
                created_at__year=year
            ).order_by('-created_at').first()
            
            if last_incident and last_incident.incident_id:
                try:
                    last_num = int(last_incident.incident_id.split('-')[-1])
                    new_num = last_num + 1
                except (ValueError, IndexError):
                    new_num = 1
            else:
                new_num = 1
            
            self.incident_id = f"INC-{year}-{new_num:04d}"
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.incident_id} - {self.title}"
    
    def clean(self):
        """Validate incident data"""
        super().clean()
        
        # Validate timeline
        if self.occurred_at and self.discovered_at:
            if self.occurred_at > self.discovered_at:
                raise ValidationError(_('Incident cannot occur after it was discovered'))
    
    @transaction.atomic
    def close_incident(self, user, resolution_summary, lessons_learned=''):
        """Close the incident atomically"""
        if resolution_summary:
            validate_safe_text(resolution_summary)
        if lessons_learned:
            validate_safe_text(lessons_learned)
        
        self.status = 'closed'
        self.closed_at = timezone.now()
        self.resolution_summary = resolution_summary
        self.lessons_learned = lessons_learned
        self.save()
    
    def add_to_response_team(self, email):
        """Add member to response team"""
        from django.core.validators import validate_email
        validate_email(email)
        
        if email not in self.response_team:
            self.response_team.append(email)
            self.save(update_fields=['response_team'])
    
    def log_evidence(self, description, collected_by, location=''):
        """Log evidence collection"""
        if not self.chain_of_custody:
            self.chain_of_custody = []
        
        self.chain_of_custody.append({
            'timestamp': timezone.now().isoformat(),
            'description': description,
            'collected_by': collected_by,
            'location': location,
            'hash': hashlib.sha256(
                f"{description}{collected_by}{location}".encode()
            ).hexdigest()[:16]
        })
        
        self.evidence_collected = True
        self.save(update_fields=['chain_of_custody', 'evidence_collected'])


class ComplianceFramework(models.Model):
    """Enhanced compliance framework tracking"""
    
    FRAMEWORK_CHOICES = [
        ('nist', _('NIST Cybersecurity Framework')),
        ('iso27001', _('ISO 27001')),
        ('gdpr', _('GDPR')),
        ('hipaa', _('HIPAA')),
        ('pci_dss', _('PCI DSS')),
        ('sox', _('Sarbanes-Oxley')),
        ('fisma', _('FISMA')),
        ('fedramp', _('FedRAMP')),
        ('ccpa', _('CCPA')),
        ('custom', _('Custom Framework')),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(
        _('framework name'), 
        max_length=100,
        validators=[validate_no_html]
    )
    framework_type = models.CharField(
        _('framework type'),
        max_length=20,
        choices=FRAMEWORK_CHOICES
    )
    version = models.CharField(_('version'), max_length=20, blank=True)
    description = models.TextField(
        _('description'), 
        blank=True,
        validators=[validate_safe_text]
    )
    
    # Status
    is_active = models.BooleanField(_('active'), default=True)
    compliance_percentage = models.FloatField(
        _('compliance percentage'), 
        default=0.0,
        validators=[validators.MinValueValidator(0), validators.MaxValueValidator(100)]
    )
    last_assessment = models.DateTimeField(_('last assessment'), null=True, blank=True)
    next_assessment = models.DateTimeField(_('next assessment'), null=True, blank=True)
    
    # Assessment details
    controls_total = models.PositiveIntegerField(_('total controls'), default=0)
    controls_implemented = models.PositiveIntegerField(_('implemented controls'), default=0)
    controls_partial = models.PositiveIntegerField(_('partially implemented'), default=0)
    controls_not_implemented = models.PositiveIntegerField(_('not implemented'), default=0)
    
    # Metadata
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    updated_at = models.DateTimeField(_('updated at'), auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_frameworks'
    )
    
    class Meta:
        verbose_name = _('compliance framework')
        verbose_name_plural = _('compliance frameworks')
        unique_together = [['name', 'version']]
        indexes = [
            models.Index(fields=['framework_type', 'is_active']),
            models.Index(fields=['next_assessment']),
        ]
    
    def __str__(self):
        return f"{self.name} {self.version}"
    
    def calculate_compliance(self):
        """Calculate compliance percentage"""
        if self.controls_total == 0:
            self.compliance_percentage = 0.0
        else:
            implemented = self.controls_implemented + (self.controls_partial * 0.5)
            self.compliance_percentage = (implemented / self.controls_total) * 100
        
        return self.compliance_percentage
    
    def is_assessment_due(self):
        """Check if assessment is due"""
        if not self.next_assessment:
            return True
        return timezone.now() >= self.next_assessment