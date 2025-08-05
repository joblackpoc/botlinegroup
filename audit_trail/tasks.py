from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Avg, Sum
from datetime import timedelta
import logging
import csv
import json
from io import StringIO
from .models import AuditLog, DataAccessLog, ComplianceLog, PerformanceMetric, SecurityAlert

logger = logging.getLogger(__name__)


@shared_task
def cleanup_old_audit_logs():
    """Remove audit logs older than retention period"""
    try:
        retention_days = settings.AUDIT_LOG_RETENTION_DAYS
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        # Archive important logs before deletion (in production, you'd move to cold storage)
        important_logs = AuditLog.objects.filter(
            timestamp__lt=cutoff_date,
            severity__in=['critical', 'error']
        )
        
        if important_logs.exists():
            # Call the archive function directly (it's defined below in this file)
            archive_audit_logs.delay(list(important_logs.values_list('id', flat=True)))
        
        # Delete old logs
        deleted_count, _ = AuditLog.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()
        
        # Clean up old performance metrics
        PerformanceMetric.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()
        
        # Log the cleanup
        AuditLog.log(
            action='data_deleted',
            severity='info',
            message=f'Cleaned up {deleted_count} audit logs older than {retention_days} days',
            metadata={
                'retention_days': retention_days,
                'deleted_count': deleted_count,
                'cutoff_date': cutoff_date.isoformat()
            }
        )
        
        logger.info(f"Cleaned up {deleted_count} old audit logs")
        return f"Cleaned up {deleted_count} old audit logs"
        
    except Exception as e:
        logger.error(f"Error cleaning up audit logs: {str(e)}")
        raise


@shared_task
def archive_audit_logs(log_ids):
    """Archive audit logs to cold storage"""
    try:
        # In production, you would:
        # 1. Export logs to a file (CSV, JSON, or Parquet)
        # 2. Compress the file
        # 3. Upload to cold storage (S3 Glacier, Azure Archive, etc.)
        # 4. Store reference in database
        
        logs = AuditLog.objects.filter(id__in=log_ids)
        
        # Create archive data
        archive_data = []
        for log in logs:
            archive_data.append({
                'id': str(log.id),
                'action': log.action,
                'severity': log.severity,
                'timestamp': log.timestamp.isoformat(),
                'user': str(log.user.id) if log.user else None,
                'user_email': log.user.email if log.user else None,
                'ip_address': log.ip_address,
                'message': log.message,
                'metadata': log.metadata,
                'object_repr': log.object_repr,
            })
        
        # In production, save to cold storage
        # For now, just log
        logger.info(f"Archived {len(archive_data)} audit logs")
        
        return f"Archived {len(archive_data)} audit logs"
        
    except Exception as e:
        logger.error(f"Error archiving audit logs: {str(e)}")
        raise


@shared_task
def generate_compliance_report(report_type='monthly'):
    """Generate compliance reports"""
    try:
        if report_type == 'monthly':
            start_date = timezone.now().replace(day=1) - timedelta(days=1)
            start_date = start_date.replace(day=1)
            end_date = timezone.now().replace(day=1) - timedelta(seconds=1)
        else:  # weekly
            start_date = timezone.now() - timedelta(days=7)
            end_date = timezone.now()
        
        # Gather compliance data
        compliance_data = {
            'report_period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'type': report_type
            },
            'user_activity': {
                'total_logins': AuditLog.objects.filter(
                    action='login',
                    timestamp__range=[start_date, end_date]
                ).count(),
                'unique_users': AuditLog.objects.filter(
                    action='login',
                    timestamp__range=[start_date, end_date]
                ).values('user').distinct().count(),
                'failed_logins': AuditLog.objects.filter(
                    action='login_failed',
                    timestamp__range=[start_date, end_date]
                ).count(),
            },
            'security_events': {
                'total_alerts': SecurityAlert.objects.filter(
                    created_at__range=[start_date, end_date]
                ).count(),
                'critical_alerts': SecurityAlert.objects.filter(
                    created_at__range=[start_date, end_date],
                    severity='critical'
                ).count(),
                'resolved_alerts': SecurityAlert.objects.filter(
                    resolved_at__range=[start_date, end_date]
                ).count(),
            },
            'data_access': {
                'total_access': DataAccessLog.objects.filter(
                    timestamp__range=[start_date, end_date]
                ).count(),
                'unique_users': DataAccessLog.objects.filter(
                    timestamp__range=[start_date, end_date]
                ).values('user').distinct().count(),
                'export_operations': DataAccessLog.objects.filter(
                    timestamp__range=[start_date, end_date],
                    access_type='export'
                ).count(),
            },
            'compliance_activities': {
                'gdpr_requests': ComplianceLog.objects.filter(
                    timestamp__range=[start_date, end_date],
                    compliance_type='gdpr_request'
                ).count(),
                'data_deletions': ComplianceLog.objects.filter(
                    timestamp__range=[start_date, end_date],
                    compliance_type='data_deletion'
                ).count(),
                'audits_completed': ComplianceLog.objects.filter(
                    completed_at__range=[start_date, end_date],
                    compliance_type='audit_review'
                ).count(),
            }
        }
        
        # Create compliance log entry
        ComplianceLog.objects.create(
            compliance_type='audit_review',
            description=f'{report_type.capitalize()} compliance report generated',
            requestor='System',
            status='completed',
            completed_at=timezone.now(),
            evidence=compliance_data,
            outcome='Report generated successfully'
        )
        
        logger.info(f"Generated {report_type} compliance report")
        return compliance_data
        
    except Exception as e:
        logger.error(f"Error generating compliance report: {str(e)}")
        raise


@shared_task
def analyze_user_behavior(user_id):
    """Analyze user behavior for anomaly detection"""
    try:
        from accounts.models import CustomUser
        
        user = CustomUser.objects.get(id=user_id)
        
        # Get user's activity for the last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        
        user_logs = AuditLog.objects.filter(
            user=user,
            timestamp__gte=thirty_days_ago
        )
        
        # Analyze patterns
        activity_by_hour = user_logs.extra(
            select={'hour': 'EXTRACT(hour FROM timestamp)'}
        ).values('hour').annotate(count=Count('id'))
        
        activity_by_action = user_logs.values('action').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Check for anomalies
        anomalies = []
        
        # Check for unusual activity times
        night_activity = user_logs.filter(
            timestamp__hour__in=[0, 1, 2, 3, 4, 5]
        ).count()
        
        if night_activity > user_logs.count() * 0.3:  # More than 30% at night
            anomalies.append({
                'type': 'unusual_hours',
                'description': 'High percentage of activity during night hours',
                'percentage': (night_activity / user_logs.count()) * 100
            })
        
        # Check for rapid data access
        rapid_access = DataAccessLog.objects.filter(
            user=user,
            timestamp__gte=timezone.now() - timedelta(hours=1)
        ).count()
        
        if rapid_access > 50:
            anomalies.append({
                'type': 'rapid_data_access',
                'description': 'Unusually high data access rate',
                'count': rapid_access
            })
        
        # Store analysis results
        if anomalies:
            from security_suite.models import SecurityAlert
            
            SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='medium',
                title=f'Anomalous behavior detected for user {user.email}',
                description='User behavior analysis detected unusual patterns',
                user=user,
                details={
                    'anomalies': anomalies,
                    'analysis_period': '30 days',
                    'total_activities': user_logs.count()
                }
            )
        
        return {
            'user': user.email,
            'anomalies_found': len(anomalies),
            'anomalies': anomalies
        }
        
    except Exception as e:
        logger.error(f"Error analyzing user behavior: {str(e)}")
        raise


@shared_task
def export_audit_logs_to_csv(start_date, end_date, user_email):
    """Export audit logs to CSV and email to user"""
    try:
        from django.core.mail import EmailMessage
        from accounts.models import CustomUser
        
        # Get logs
        logs = AuditLog.objects.filter(
            timestamp__range=[start_date, end_date]
        ).order_by('-timestamp')
        
        # Create CSV
        csv_buffer = StringIO()
        csv_writer = csv.writer(csv_buffer)
        
        # Write headers
        csv_writer.writerow([
            'Timestamp', 'Action', 'Severity', 'User', 'IP Address',
            'Message', 'Object', 'Metadata'
        ])
        
        # Write data
        for log in logs:
            csv_writer.writerow([
                log.timestamp.isoformat(),
                log.get_action_display(),
                log.get_severity_display(),
                log.user.email if log.user else 'System',
                log.ip_address or 'N/A',
                log.message,
                log.object_repr or 'N/A',
                json.dumps(log.metadata) if log.metadata else '{}'
            ])
        
        # Send email with attachment
        email = EmailMessage(
            subject=f'Audit Log Export - {start_date} to {end_date}',
            body='Please find attached the requested audit log export.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user_email],
        )
        
        csv_buffer.seek(0)
        email.attach(
            f'audit_logs_{start_date}_{end_date}.csv',
            csv_buffer.getvalue(),
            'text/csv'
        )
        
        email.send()
        
        # Log the export
        user = CustomUser.objects.get(email=user_email)
        DataAccessLog.objects.create(
            user=user,
            access_type='export',
            data_type='audit_logs',
            data_identifier=f'{start_date} to {end_date}',
            purpose='Audit log export',
            ip_address='127.0.0.1',  # System generated
            success=True,
            records_accessed=logs.count()
        )
        
        logger.info(f"Exported {logs.count()} audit logs for {user_email}")
        return f"Exported {logs.count()} audit logs"
        
    except Exception as e:
        logger.error(f"Error exporting audit logs: {str(e)}")
        raise


@shared_task
def calculate_system_metrics():
    """Calculate and store system performance metrics"""
    try:
        # Calculate average response time for last hour
        one_hour_ago = timezone.now() - timedelta(hours=1)
        
        avg_response_time = PerformanceMetric.objects.filter(
            metric_type='response_time',
            timestamp__gte=one_hour_ago
        ).aggregate(avg=Avg('value'))['avg']
        
        if avg_response_time:
            PerformanceMetric.objects.create(
                metric_type='response_time',
                value=avg_response_time,
                unit='ms',
                endpoint='system_average',
                metadata={'calculation': 'hourly_average'}
            )
        
        # Calculate error rate
        total_requests = PerformanceMetric.objects.filter(
            metric_type='response_time',
            timestamp__gte=one_hour_ago
        ).count()
        
        error_count = PerformanceMetric.objects.filter(
            metric_type='error_rate',
            timestamp__gte=one_hour_ago
        ).aggregate(total=Sum('value'))['total'] or 0
        
        if total_requests > 0:
            error_rate = (error_count / total_requests) * 100
            PerformanceMetric.objects.create(
                metric_type='error_rate',
                value=error_rate,
                unit='percentage',
                endpoint='system_average',
                metadata={
                    'calculation': 'hourly_average',
                    'total_requests': total_requests,
                    'error_count': error_count
                }
            )
        
        # Calculate active users
        from accounts.models import CustomUser
        active_users = CustomUser.objects.filter(
            last_activity__gte=one_hour_ago
        ).count()
        
        PerformanceMetric.objects.create(
            metric_type='active_users',
            value=active_users,
            unit='count',
            metadata={'period': 'last_hour'}
        )
        
        logger.info("System metrics calculated successfully")
        return "Metrics calculated"
        
    except Exception as e:
        logger.error(f"Error calculating system metrics: {str(e)}")
        raise