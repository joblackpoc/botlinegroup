# audit_trail/views.py

from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.db.models import Count, Q, F, Avg, Max, Min
from django.utils import timezone
from django.http import HttpResponse
from django.conf import settings
from datetime import timedelta
import csv
import json

from .models import AuditLog, DataAccessLog, ComplianceLog, PerformanceMetric
from .serializers import (
    AuditLogSerializer, DataAccessLogSerializer, ComplianceLogSerializer,
    PerformanceMetricSerializer, AuditSearchSerializer, MetricsChartSerializer
)
from accounts.permissions import IsAdminUser, IsSuperUser
from .tasks import export_audit_logs_to_csv, generate_compliance_report


class AuditLogListView(generics.ListAPIView):
    """List audit logs with filtering"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = AuditLogSerializer
    
    def get_queryset(self):
        queryset = AuditLog.objects.all()
        
        # Filter by action
        action = self.request.query_params.get('action')
        if action:
            queryset = queryset.filter(action=action)
        
        # Filter by severity
        severity = self.request.query_params.get('severity')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by user
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by IP
        ip_address = self.request.query_params.get('ip_address')
        if ip_address:
            queryset = queryset.filter(ip_address=ip_address)
        
        # Date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date and end_date:
            queryset = queryset.filter(
                timestamp__date__range=[start_date, end_date]
            )
        
        # Search in message
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(message__icontains=search) |
                Q(search_vector__icontains=search)
            )
        
        return queryset.order_by('-timestamp')


class AuditLogDetailView(generics.RetrieveAPIView):
    """Get audit log details"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = AuditLogSerializer
    queryset = AuditLog.objects.all()


class ExportAuditLogsView(APIView):
    """Export audit logs to CSV"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        # Get date range
        start_date = request.data.get('start_date')
        end_date = request.data.get('end_date')
        
        if not start_date or not end_date:
            return Response(
                {'error': 'start_date and end_date are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Queue export task
        export_audit_logs_to_csv.delay(
            start_date,
            end_date,
            request.user.email
        )
        
        return Response({
            'message': 'Export queued. You will receive an email with the CSV file.'
        })


class SearchAuditLogsView(APIView):
    """Advanced search for audit logs"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        serializer = AuditSearchSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Build query
        queryset = AuditLog.objects.all()
        
        # Apply filters from serializer
        filters = serializer.validated_data
        
        if filters.get('actions'):
            queryset = queryset.filter(action__in=filters['actions'])
        
        if filters.get('severities'):
            queryset = queryset.filter(severity__in=filters['severities'])
        
        if filters.get('users'):
            queryset = queryset.filter(user_id__in=filters['users'])
        
        if filters.get('ip_addresses'):
            queryset = queryset.filter(ip_address__in=filters['ip_addresses'])
        
        if filters.get('start_date'):
            queryset = queryset.filter(timestamp__gte=filters['start_date'])
        
        if filters.get('end_date'):
            queryset = queryset.filter(timestamp__lte=filters['end_date'])
        
        if filters.get('search_text'):
            queryset = queryset.filter(
                Q(message__icontains=filters['search_text']) |
                Q(search_vector__icontains=filters['search_text'])
            )
        
        # Order and limit
        queryset = queryset.order_by('-timestamp')[:1000]
        
        # Serialize results
        results = AuditLogSerializer(queryset, many=True).data
        
        return Response({
            'count': len(results),
            'results': results
        })


class DataAccessLogListView(generics.ListAPIView):
    """List data access logs"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = DataAccessLogSerializer
    
    def get_queryset(self):
        queryset = DataAccessLog.objects.all()
        
        # Filter by access type
        access_type = self.request.query_params.get('access_type')
        if access_type:
            queryset = queryset.filter(access_type=access_type)
        
        # Filter by data type
        data_type = self.request.query_params.get('data_type')
        if data_type:
            queryset = queryset.filter(data_type=data_type)
        
        # Filter by user
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        return queryset.order_by('-timestamp')


class DataAccessLogDetailView(generics.RetrieveAPIView):
    """Get data access log details"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = DataAccessLogSerializer
    queryset = DataAccessLog.objects.all()


class DataAccessReportView(APIView):
    """Generate data access report"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        # Time period
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Aggregate data
        access_summary = DataAccessLog.objects.filter(
            timestamp__gte=start_date
        ).values('access_type').annotate(
            count=Count('id'),
            unique_users=Count('user', distinct=True),
            total_records=Count('records_accessed')
        )
        
        data_type_summary = DataAccessLog.objects.filter(
            timestamp__gte=start_date
        ).values('data_type').annotate(
            count=Count('id'),
            unique_users=Count('user', distinct=True)
        ).order_by('-count')[:10]
        
        top_users = DataAccessLog.objects.filter(
            timestamp__gte=start_date
        ).values('user__email').annotate(
            access_count=Count('id'),
            total_records=Count('records_accessed')
        ).order_by('-access_count')[:10]
        
        return Response({
            'period_days': days,
            'access_summary': list(access_summary),
            'data_type_summary': list(data_type_summary),
            'top_users': list(top_users),
        })


class ComplianceLogListView(generics.ListCreateAPIView):
    """List and create compliance logs"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = ComplianceLogSerializer
    
    def get_queryset(self):
        queryset = ComplianceLog.objects.all()
        
        # Filter by type
        compliance_type = self.request.query_params.get('type')
        if compliance_type:
            queryset = queryset.filter(compliance_type=compliance_type)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        return queryset.order_by('-timestamp')
    
    def perform_create(self, serializer):
        serializer.save(reviewer=self.request.user)


class CreateComplianceLogView(ComplianceLogListView):
    """Alias for creating compliance log"""
    pass


class ComplianceLogDetailView(generics.RetrieveUpdateAPIView):
    """Get and update compliance log"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = ComplianceLogSerializer
    queryset = ComplianceLog.objects.all()
    
    def perform_update(self, serializer):
        if 'status' in serializer.validated_data:
            if serializer.validated_data['status'] == 'completed':
                serializer.save(
                    completed_at=timezone.now(),
                    reviewer=self.request.user
                )
            else:
                serializer.save(reviewer=self.request.user)
        else:
            serializer.save()


class UpdateComplianceLogView(ComplianceLogDetailView):
    """Alias for updating compliance log"""
    pass


class PerformanceMetricsView(APIView):
    """Get performance metrics"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        # Time period
        period = request.query_params.get('period', '24h')
        metric_type = request.query_params.get('type', 'all')
        
        # Determine time range
        now = timezone.now()
        if period == '1h':
            start_time = now - timedelta(hours=1)
        elif period == '7d':
            start_time = now - timedelta(days=7)
        elif period == '30d':
            start_time = now - timedelta(days=30)
        else:  # Default 24h
            start_time = now - timedelta(hours=24)
        
        # Build query
        queryset = PerformanceMetric.objects.filter(
            timestamp__gte=start_time
        )
        
        if metric_type != 'all':
            queryset = queryset.filter(metric_type=metric_type)
        
        # Get latest metrics
        latest_metrics = {}
        for metric_type in ['response_time', 'error_rate', 'active_users']:
            latest = queryset.filter(
                metric_type=metric_type
            ).order_by('-timestamp').first()
            
            if latest:
                latest_metrics[metric_type] = {
                    'value': latest.value,
                    'unit': latest.unit,
                    'timestamp': latest.timestamp.isoformat(),
                    'is_warning': latest.is_warning,
                    'is_critical': latest.is_critical,
                }
        
        # Get metric trends
        trends = queryset.values(
            'metric_type',
            'timestamp__hour'
        ).annotate(
            avg_value=Avg('value'),
            max_value=Max('value'),
            min_value=Min('value')
        ).order_by('metric_type', 'timestamp__hour')
        
        return Response({
            'period': period,
            'latest_metrics': latest_metrics,
            'trends': list(trends),
        })


class MetricsChartDataView(APIView):
    """Get metrics data for charts"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        metric_type = request.query_params.get('type', 'response_time')
        period = request.query_params.get('period', '24h')
        
        # Determine time range and interval
        now = timezone.now()
        if period == '1h':
            start_time = now - timedelta(hours=1)
            interval = 'minute'
        elif period == '7d':
            start_time = now - timedelta(days=7)
            interval = 'day'
        elif period == '30d':
            start_time = now - timedelta(days=30)
            interval = 'day'
        else:  # Default 24h
            start_time = now - timedelta(hours=24)
            interval = 'hour'
        
        # Get metrics
        metrics = PerformanceMetric.objects.filter(
            metric_type=metric_type,
            timestamp__gte=start_time
        ).order_by('timestamp')
        
        # Format for charts
        chart_data = {
            'labels': [],
            'datasets': [{
                'label': metric_type.replace('_', ' ').title(),
                'data': [],
                'borderColor': 'rgb(75, 192, 192)',
                'tension': 0.1
            }]
        }
        
        for metric in metrics:
            if interval == 'minute':
                label = metric.timestamp.strftime('%H:%M')
            elif interval == 'hour':
                label = metric.timestamp.strftime('%H:00')
            else:  # day
                label = metric.timestamp.strftime('%m/%d')
            
            chart_data['labels'].append(label)
            chart_data['datasets'][0]['data'].append(metric.value)
        
        return Response(chart_data)


class ExportMetricsView(APIView):
    """Export metrics to CSV"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        # Get parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        metric_type = request.query_params.get('type', 'all')
        
        # Build query
        queryset = PerformanceMetric.objects.all()
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)
        if metric_type != 'all':
            queryset = queryset.filter(metric_type=metric_type)
        
        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="performance_metrics.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Timestamp', 'Metric Type', 'Value', 'Unit', 'Endpoint', 'User Count', 'Metadata'])
        
        for metric in queryset.order_by('-timestamp'):
            writer.writerow([
                metric.timestamp.isoformat(),
                metric.get_metric_type_display(),
                metric.value,
                metric.unit,
                metric.endpoint or 'N/A',
                metric.user_count,
                json.dumps(metric.metadata) if metric.metadata else '{}'
            ])
        
        return response


class ActivityTimelineView(APIView):
    """Get activity timeline"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        # Time period
        days = int(request.query_params.get('days', 7))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Build timeline
        timeline = []
        
        for i in range(days):
            date = (start_date + timedelta(days=i)).date()
            
            # Get activities for this date
            activities = {
                'date': date.isoformat(),
                'logins': AuditLog.objects.filter(
                    action='login',
                    timestamp__date=date
                ).count(),
                'failed_logins': AuditLog.objects.filter(
                    action='login_failed',
                    timestamp__date=date
                ).count(),
                'user_changes': AuditLog.objects.filter(
                    action__in=['user_created', 'user_updated', 'user_deleted'],
                    timestamp__date=date
                ).count(),
                'config_changes': AuditLog.objects.filter(
                    action='config_changed',
                    timestamp__date=date
                ).count(),
                'security_alerts': AuditLog.objects.filter(
                    action='security_alert',
                    timestamp__date=date
                ).count(),
                'data_access': DataAccessLog.objects.filter(
                    timestamp__date=date
                ).count(),
            }
            
            timeline.append(activities)
        
        return Response({
            'period_days': days,
            'timeline': timeline
        })


class UserActivityTimelineView(APIView):
    """Get activity timeline for specific user"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request, user_id):
        # Verify user exists
        from accounts.models import CustomUser
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Time period
        days = int(request.query_params.get('days', 30))
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Get user activities
        activities = AuditLog.objects.filter(
            user=user,
            timestamp__range=[start_date, end_date]
        ).order_by('-timestamp')
        
        # Group by date
        timeline = {}
        for activity in activities:
            date_key = activity.timestamp.date().isoformat()
            if date_key not in timeline:
                timeline[date_key] = []
            
            timeline[date_key].append({
                'time': activity.timestamp.time().isoformat(),
                'action': activity.get_action_display(),
                'severity': activity.severity,
                'message': activity.message,
                'ip_address': activity.ip_address,
            })
        
        # Get user statistics
        stats = {
            'total_activities': activities.count(),
            'login_count': activities.filter(action='login').count(),
            'failed_login_count': activities.filter(action='login_failed').count(),
            'data_access_count': DataAccessLog.objects.filter(
                user=user,
                timestamp__range=[start_date, end_date]
            ).count(),
            'unique_ips': activities.values('ip_address').distinct().count(),
        }
        
        return Response({
            'user': {
                'id': str(user.id),
                'email': user.email,
                'name': user.get_full_name(),
            },
            'period_days': days,
            'statistics': stats,
            'timeline': timeline,
        })


class AuditReportsView(APIView):
    """Generate various audit reports"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        report_type = request.query_params.get('type', 'summary')
        
        # Generate appropriate report
        if report_type == 'summary':
            return self._generate_summary_report(request)
        elif report_type == 'security':
            return self._generate_security_report(request)
        elif report_type == 'compliance':
            return self._generate_compliance_report(request)
        elif report_type == 'user':
            return self._generate_user_report(request)
        else:
            return Response(
                {'error': 'Invalid report type'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _generate_summary_report(self, request):
        """Generate summary audit report"""
        days = int(request.query_params.get('days', 7))
        start_date = timezone.now() - timedelta(days=days)
        
        summary = {
            'period_days': days,
            'audit_logs': {
                'total': AuditLog.objects.filter(
                    timestamp__gte=start_date
                ).count(),
                'by_severity': dict(
                    AuditLog.objects.filter(
                        timestamp__gte=start_date
                    ).values_list('severity').annotate(count=Count('id'))
                ),
                'by_action': dict(
                    AuditLog.objects.filter(
                        timestamp__gte=start_date
                    ).values_list('action').annotate(count=Count('id'))[:10]
                ),
            },
            'data_access': {
                'total': DataAccessLog.objects.filter(
                    timestamp__gte=start_date
                ).count(),
                'by_type': dict(
                    DataAccessLog.objects.filter(
                        timestamp__gte=start_date
                    ).values_list('access_type').annotate(count=Count('id'))
                ),
            },
            'compliance': {
                'total': ComplianceLog.objects.filter(
                    timestamp__gte=start_date
                ).count(),
                'completed': ComplianceLog.objects.filter(
                    completed_at__gte=start_date
                ).count(),
            },
            'top_users': list(
                AuditLog.objects.filter(
                    timestamp__gte=start_date,
                    user__isnull=False
                ).values('user__email').annotate(
                    activity_count=Count('id')
                ).order_by('-activity_count')[:10]
            ),
        }
        
        return Response(summary)
    
    def _generate_security_report(self, request):
        """Generate security-focused audit report"""
        days = int(request.query_params.get('days', 30))
        start_date = timezone.now() - timedelta(days=days)
        
        # Queue report generation
        generate_compliance_report.delay('security')
        
        return Response({
            'message': 'Security report generation queued',
            'type': 'security',
            'period_days': days
        })
    
    def _generate_compliance_report(self, request):
        """Generate compliance audit report"""
        report_type = request.query_params.get('compliance_type', 'monthly')
        
        # Queue report generation
        generate_compliance_report.delay(report_type)
        
        return Response({
            'message': 'Compliance report generation queued',
            'type': report_type
        })
    
    def _generate_user_report(self, request):
        """Generate user activity report"""
        user_id = request.query_params.get('user_id')
        if not user_id:
            return Response(
                {'error': 'user_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Redirect to user timeline
        return UserActivityTimelineView.as_view()(request, user_id)


class RetentionManagementView(APIView):
    """Manage audit log retention"""
    permission_classes = [permissions.IsAuthenticated, IsSuperUser]
    
    def get(self, request):
        """Get retention statistics"""
        retention_days = settings.AUDIT_LOG_RETENTION_DAYS
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        stats = {
            'retention_days': retention_days,
            'total_logs': AuditLog.objects.count(),
            'logs_to_archive': AuditLog.objects.filter(
                timestamp__lt=cutoff_date
            ).count(),
            'oldest_log': AuditLog.objects.order_by('timestamp').first(),
            'storage_estimate_mb': AuditLog.objects.count() * 0.001,  # Rough estimate
        }
        
        if stats['oldest_log']:
            stats['oldest_log'] = {
                'timestamp': stats['oldest_log'].timestamp.isoformat(),
                'age_days': (timezone.now() - stats['oldest_log'].timestamp).days
            }
        
        return Response(stats)
    
    def post(self, request):
        """Trigger retention cleanup"""
        action = request.data.get('action')
        
        if action == 'cleanup':
            from .tasks import cleanup_old_audit_logs
            cleanup_old_audit_logs.delay()
            
            return Response({
                'message': 'Audit log cleanup queued'
            })
        else:
            return Response(
                {'error': 'Invalid action'},
                status=status.HTTP_400_BAD_REQUEST
            )


class CleanupOldLogsView(RetentionManagementView):
    """Alias for cleanup action"""
    pass