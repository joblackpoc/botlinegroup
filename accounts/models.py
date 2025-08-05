from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.base_user import BaseUserManager
from cryptography.fernet import Fernet
from django.conf import settings
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import timedelta
import uuid


class CustomUserManager(BaseUserManager):
    """Custom user manager for email-based authentication"""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_approved', True)
        extra_fields.setdefault('approval_status', 'approved')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """Custom user model with enhanced security features"""
    
    APPROVAL_STATUS_CHOICES = (
        ('pending', _('Pending')),
        ('approved', _('Approved')),
        ('rejected', _('Rejected')),
        ('suspended', _('Suspended')),
    )
    
    USER_TYPE_CHOICES = (
        ('admin', _('Admin')),
        ('user', _('User')),
    )
    
    # Basic Information
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    
    # LINE Information
    line_user_id = models.CharField(_('LINE user ID'), max_length=255, unique=True, null=True, blank=True)
    line_display_name = models.CharField(_('LINE display name'), max_length=255, blank=True)
    
    # Security Features
    is_active = models.BooleanField(_('active'), default=True)
    is_staff = models.BooleanField(_('staff status'), default=False)
    is_approved = models.BooleanField(_('approved'), default=False)
    approval_status = models.CharField(
        _('approval status'),
        max_length=20,
        choices=APPROVAL_STATUS_CHOICES,
        default='pending'
    )
    user_type = models.CharField(
        _('user type'),
        max_length=20,
        choices=USER_TYPE_CHOICES,
        default='user'
    )
    
    # MFA Settings
    mfa_enabled = models.BooleanField(_('MFA enabled'), default=False)
    mfa_secret = models.CharField(_('MFA secret'), max_length=255, blank=True)
    mfa_backup_codes = models.JSONField(_('MFA backup codes'), default=list, blank=True)
    mfa_enforced_at = models.DateTimeField(_('MFA enforced at'), null=True, blank=True)
    
    # Timestamps
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    last_login = models.DateTimeField(_('last login'), null=True, blank=True)
    last_activity = models.DateTimeField(_('last activity'), null=True, blank=True)
    approved_at = models.DateTimeField(_('approved at'), null=True, blank=True)
    approved_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='approved_users'
    )
    
    # Security Metadata
    last_password_change = models.DateTimeField(_('last password change'), default=timezone.now)
    password_history = models.JSONField(_('password history'), default=list, blank=True)
    failed_login_attempts = models.IntegerField(_('failed login attempts'), default=0)
    last_failed_login = models.DateTimeField(_('last failed login'), null=True, blank=True)
    
    # IP Tracking
    last_login_ip = models.GenericIPAddressField(_('last login IP'), null=True, blank=True)
    registration_ip = models.GenericIPAddressField(_('registration IP'), null=True, blank=True)
    
    # Session Management
    active_sessions = models.JSONField(_('active sessions'), default=list, blank=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['line_user_id']),
            models.Index(fields=['approval_status']),
            models.Index(fields=['last_activity']),
        ]
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in between."""
        full_name = f'{self.first_name} {self.last_name}'.strip()
        return full_name or self.email
    
    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name or self.email.split('@')[0]
    
    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.user_type == 'admin' or self.is_superuser
    
    @property
    def requires_mfa_setup(self):
        """Check if user needs to setup MFA"""
        if self.is_superuser:
            return False
        return not self.mfa_enabled and self.last_login is not None
    
    def generate_mfa_secret(self):
        """Generate a new MFA secret"""
        secret = pyotp.random_base32()
        # Encrypt the secret before storing
        fernet = Fernet(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        self.mfa_secret = fernet.encrypt(secret.encode()).decode()
        self.save()
        return secret
    
    def get_mfa_secret(self):
        """Get decrypted MFA secret"""
        if not self.mfa_secret:
            return None
        fernet = Fernet(settings.SECRET_KEY[:32].encode().ljust(32)[:32])
        return fernet.decrypt(self.mfa_secret.encode()).decode()
    
    def generate_mfa_qr_code(self):
        """Generate QR code for MFA setup"""
        secret = self.get_mfa_secret()
        if not secret:
            secret = self.generate_mfa_secret()
        
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=self.email,
            issuer_name=settings.OTP_TOTP_ISSUER
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    def verify_mfa_token(self, token):
        """Verify MFA token"""
        secret = self.get_mfa_secret()
        if not secret:
            return False
        
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    def generate_backup_codes(self):
        """Generate MFA backup codes"""
        codes = []
        for _ in range(10):
            code = ''.join([str(uuid.uuid4().int)[:8]])
            codes.append(code)
        
        # Hash the codes before storing
        from django.contrib.auth.hashers import make_password
        self.mfa_backup_codes = [make_password(code) for code in codes]
        self.save()
        
        return codes
    
    def use_backup_code(self, code):
        """Use a backup code for authentication"""
        from django.contrib.auth.hashers import check_password
        
        for i, hashed_code in enumerate(self.mfa_backup_codes):
            if check_password(code, hashed_code):
                # Remove used code
                self.mfa_backup_codes.pop(i)
                self.save()
                return True
        return False
    
    def record_login(self, ip_address=None, session_key=None):
        """Record successful login"""
        self.last_login = timezone.now()
        self.last_activity = timezone.now()
        self.failed_login_attempts = 0
        self.last_failed_login = None
        
        if ip_address:
            self.last_login_ip = ip_address
        
        if session_key:
            # Store session info
            session_info = {
                'session_key': session_key,
                'login_time': timezone.now().isoformat(),
                'ip_address': ip_address,
            }
            self.active_sessions.append(session_info)
            # Keep only last 5 sessions
            self.active_sessions = self.active_sessions[-5:]
        
        self.save()
    
    def record_failed_login(self, ip_address=None):
        """Record failed login attempt"""
        self.failed_login_attempts += 1
        self.last_failed_login = timezone.now()
        self.save()
    
    def is_locked_out(self):
        """Check if user is locked out due to failed attempts"""
        if self.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            if self.last_failed_login:
                lockout_duration = timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
                return timezone.now() < self.last_failed_login + lockout_duration
        return False
    
    def update_password_history(self, password_hash):
        """Update password history"""
        self.password_history.append({
            'hash': password_hash,
            'changed_at': timezone.now().isoformat()
        })
        # Keep only last N passwords
        self.password_history = self.password_history[-settings.PASSWORD_HISTORY_COUNT:]
        self.last_password_change = timezone.now()
        self.save()
    
    def approve_user(self, approved_by):
        """Approve user registration"""
        self.is_approved = True
        self.approval_status = 'approved'
        self.approved_at = timezone.now()
        self.approved_by = approved_by
        self.save()
    
    def reject_user(self, rejected_by):
        """Reject user registration"""
        self.is_approved = False
        self.approval_status = 'rejected'
        self.approved_at = timezone.now()
        self.approved_by = rejected_by
        self.save()
    
    def suspend_user(self, suspended_by):
        """Suspend user account"""
        self.is_active = False
        self.approval_status = 'suspended'
        self.save()


class PasswordHistory(models.Model):
    """Track password history for users"""
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='password_histories')
    password_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.created_at}"
