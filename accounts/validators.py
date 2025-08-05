from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from django.contrib.auth.password_validation import get_password_validators
from django.contrib.auth.hashers import check_password
import re
from datetime import datetime, timedelta
from django.utils import timezone


class CustomPasswordValidator:
    """
    Enhanced password validator following NIST 800-63B guidelines and 
    additional security best practices for 2025
    """
    
    def __init__(self):
        self.min_length = 12
        self.max_length = 128
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_special = True
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Common patterns to avoid
        self.common_patterns = [
            r'(.)\1{2,}',  # Same character repeated 3+ times
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
            r'(qwerty|asdfgh|zxcvbn)',  # Keyboard patterns
            r'(password|admin|user|login|welcome|letmein)',  # Common words
        ]
        
        # Breached passwords list (in production, use a larger database)
        self.breached_passwords = {
            'password123', 'admin123', 'letmein123', 'welcome123',
            'qwerty123', 'password1', 'password123!', '123456789',
            'iloveyou', 'monkey123', 'dragon123', 'baseball1',
        }
        
    def validate(self, password, user=None):
        """Validate password against security requirements"""
        
        # Length check
        if len(password) < self.min_length:
            raise ValidationError(
                _("Password must be at least %(min_length)d characters long."),
                code='password_too_short',
                params={'min_length': self.min_length},
            )
        
        if len(password) > self.max_length:
            raise ValidationError(
                _("Password must be no more than %(max_length)d characters long."),
                code='password_too_long',
                params={'max_length': self.max_length},
            )
        
        # Character requirements
        errors = []
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append(_("Password must contain at least one uppercase letter."))
        
        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append(_("Password must contain at least one lowercase letter."))
        
        if self.require_numbers and not re.search(r'[0-9]', password):
            errors.append(_("Password must contain at least one number."))
        
        if self.require_special and not re.search(rf'[{re.escape(self.special_chars)}]', password):
            errors.append(_("Password must contain at least one special character: %(chars)s") % {'chars': self.special_chars})
        
        # Check for common patterns
        for pattern in self.common_patterns:
            if re.search(pattern, password.lower()):
                errors.append(_("Password contains common patterns or sequences. Please choose a more complex password."))
                break
        
        # Check against breached passwords
        if password.lower() in self.breached_passwords:
            errors.append(_("This password has been found in data breaches. Please choose a different password."))
        
        # Check password doesn't contain user information
        if user:
            user_info = [
                user.email.split('@')[0] if hasattr(user, 'email') else '',
                getattr(user, 'first_name', ''),
                getattr(user, 'last_name', ''),
                getattr(user, 'line_display_name', ''),
            ]
            
            for info in user_info:
                if info and len(info) > 2 and info.lower() in password.lower():
                    errors.append(_("Password cannot contain your personal information."))
                    break
        
        # Check password history if user exists
        if user and hasattr(user, 'password_history'):
            for history_entry in user.password_history[-12:]:  # Check last 12 passwords
                if check_password(password, history_entry.get('hash', '')):
                    errors.append(_("Password has been used recently. Please choose a different password."))
                    break
        
        # Check for dictionary words (simple check)
        if len(password) <= 10 and password.lower().isalpha():
            errors.append(_("Password appears to be a dictionary word. Please add numbers and special characters."))
        
        # Raise all errors at once
        if errors:
            raise ValidationError(errors)
        
    def get_help_text(self):
        return _(
            "Your password must:\n"
            "• Be at least %(min_length)d characters long\n"
            "• Contain at least one uppercase letter (A-Z)\n"
            "• Contain at least one lowercase letter (a-z)\n"
            "• Contain at least one number (0-9)\n"
            "• Contain at least one special character: %(special_chars)s\n"
            "• Not contain common patterns or your personal information\n"
            "• Not be a password that has been found in data breaches"
        ) % {
            'min_length': self.min_length,
            'special_chars': self.special_chars
        }


class PasswordExpiryValidator:
    """Check if password has expired based on policy"""
    
    def __init__(self, expiry_days=90):
        self.expiry_days = expiry_days
    
    def validate(self, password, user=None):
        """Check if user's password has expired"""
        if user and hasattr(user, 'last_password_change'):
            expiry_date = user.last_password_change + timedelta(days=self.expiry_days)
            if timezone.now() > expiry_date:
                raise ValidationError(
                    _("Your password has expired. Please set a new password."),
                    code='password_expired',
                )
    
    def password_expires_soon(self, user, warning_days=7):
        """Check if password expires soon"""
        if user and hasattr(user, 'last_password_change'):
            expiry_date = user.last_password_change + timedelta(days=self.expiry_days)
            warning_date = expiry_date - timedelta(days=warning_days)
            return timezone.now() > warning_date
        return False
    
    def get_help_text(self):
        return _("Passwords expire every %(days)d days for security reasons.") % {'days': self.expiry_days}