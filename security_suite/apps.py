from django.apps import AppConfig
from django.db.models.signals import post_migrate


class SecuritySuiteConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'security_suite'
    verbose_name = 'Security Suite'
    
    def ready(self):
        """
        Application initialization - register signals and perform checks.
        """
        # Import signal handlers
        from . import signals
        
        # Connect post-migrate signal to create default data
        post_migrate.connect(self.create_default_data, sender=self)
        
        # Register system checks
        from django.core.checks import register
        from .checks import check_security_settings
        register(check_security_settings)
    
    @staticmethod
    def create_default_data(sender, **kwargs):
        """
        Create default security configuration after migrations.
        """
        from .models import SecurityConfiguration
        
        # Create default configuration if none exists
        if not SecurityConfiguration.objects.filter(is_active=True).exists():
            SecurityConfiguration.objects.create(
                name='Default Configuration',
                is_active=True,
                max_login_attempts=5,
                lockout_duration_minutes=30,
                session_timeout_minutes=30,
                min_password_length=12,
                require_uppercase=True,
                require_lowercase=True,
                require_numbers=True,
                require_special_chars=True,
                password_expiry_days=90,
                password_history_count=12,
                mfa_required=True,
                mfa_grace_period_days=7,
                rate_limit_enabled=True,
                rate_limit_requests=100,
                rate_limit_period_seconds=3600,
                audit_retention_days=90,
                failed_login_threshold=10,
                real_time_monitoring=True,
                alert_threshold_critical=1,
                alert_threshold_high=5
            )