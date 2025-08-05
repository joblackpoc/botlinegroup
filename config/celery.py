# config/celery.py

import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('line_bot_security')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery beat schedule
app.conf.beat_schedule = {
    # Clean up expired sessions every hour
    'cleanup-expired-sessions': {
        'task': 'security_suite.tasks.cleanup_expired_sessions',
        'schedule': crontab(minute=0),  # Every hour
    },
    
    # Run security audit every 6 hours
    'security-audit': {
        'task': 'security_suite.tasks.run_security_audit',
        'schedule': crontab(minute=0, hour='*/6'),  # Every 6 hours
    },
    
    # Check for expired passwords daily
    'check-password-expiry': {
        'task': 'accounts.tasks.check_password_expiry',
        'schedule': crontab(minute=0, hour=9),  # Daily at 9 AM
    },
    
    # Clean up old audit logs
    'cleanup-audit-logs': {
        'task': 'audit_trail.tasks.cleanup_old_audit_logs',
        'schedule': crontab(minute=0, hour=2),  # Daily at 2 AM
    },
    
    # Update threat intelligence
    'update-threat-intelligence': {
        'task': 'security_suite.tasks.update_threat_intelligence',
        'schedule': crontab(minute=0, hour='*/12'),  # Every 12 hours
    },
    
    # Generate daily security report
    'daily-security-report': {
        'task': 'security_suite.tasks.generate_daily_security_report',
        'schedule': crontab(minute=0, hour=8),  # Daily at 8 AM
    },
    
    # Monitor system health
    'system-health-check': {
        'task': 'security_suite.tasks.system_health_check',
        'schedule': crontab(minute='*/5'),  # Every 5 minutes
    },
    
    # Clean up expired blacklist entries
    'cleanup-expired-blacklist': {
        'task': 'security_suite.tasks.cleanup_expired_blacklist',
        'schedule': crontab(minute=30, hour='*/2'),  # Every 2 hours
    },
}

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')