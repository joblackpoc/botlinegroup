from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django.db.models import Count, Q, Avg, Sum, Prefetch
from django.utils import timezone
from django.utils.html import escape
from django.utils.translation import gettext_lazy as _
from django.http import HttpResponse, FileResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.core.cache import cache
from django.db import transaction
from datetime import timedelta
from ipware import get_client_ip
import json
import csv
from io import StringIO
import logging
from functools import wraps

from .models import (
    SecurityAlert, IPBlacklist, SecurityConfiguration,
    SessionMonitor, ThreatIntelligence
)
from .serializers import (
    SecurityAlertSerializer, IPBlacklistSerializer,
    SecurityConfigSerializer, SessionMonitorSerializer,
    ThreatIntelligenceSerializer, DashboardDataSerializer,
    SecurityMetricsSerializer
)
from accounts.permissions import IsAdminUser, IsSuperUser
from audit_trail.models import AuditLog, PerformanceMetric
from .permissions import (
    IsAlertOwner, IsSessionOwner, CanManageBlacklist,
    CanViewSecurityData, CanModifySecurityConfig
)
from .utils import sanitize_path, mask_email, rate_limit_check
from django_ratelimit.decorators import ratelimit

logger = logging.getLogger(__name__)

# Constants for rate limiting and caching
CACHE_TTL = 300  # 5 minutes
MAX_QUERY_DAYS = 365  # Maximum days for date range queries
MAX_EXPORT_RECORDS = 10000  # Maximum records for export
DEFAULT_PAGE_SIZE = 50


class StandardResultsSetPagination(PageNumberPagination):
    """Standard pagination for API responses"""
    page_size = DEFAULT_PAGE_SIZE
    page_size_query_param = 'page_size'
    max_page_size = 100


def audit_log_decorator(action, severity='info'):
    """Decorator for automatic audit logging"""
    def decorator(func):
        @wraps(func)
        def wrapper(self, request, *args, **kwargs):
            client_ip, _ = get_client_ip(request)
            user = request.user if hasattr(request, 'user') else None
            
            try:
                response = func(self, request, *args, **kwargs)
                
                # Log successful action
                AuditLog.log(
                    action=action,
                    user=user,
                    severity=severity,
                    message=f'{action} performed successfully',
                    ip_address=client_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    metadata={
                        'view': self.__class__.__name__,
                        'method': request.method,
                        'path': sanitize_path(request.path),
                    }
                )
                
                return response
                
            except Exception as e:
                # Log failed action
                AuditLog.log(
                    action=action,
                    user=user,
                    severity='error',
                    message=f'{action} failed: {str(e)}',
                    ip_address=client_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    metadata={
                        'view': self.__class__.__name__,
                        'method': request.method,
                        'path': sanitize_path(request.path),
                        'error': str(e)
                    }
                )
                raise
                
        return wrapper
    return decorator


class DashboardDataView(APIView):
    """Get dashboard data for security monitoring with caching and optimization"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    
    @ratelimit(key='user', rate='30/m', method='GET')
    def get(self, request):
        # Check rate limit
        if getattr(request, 'limited', False):
            return Response(
                {'error': _('Rate limit exceeded. Please try again later.')},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # Try to get from cache
        cache_key = f'dashboard_data_{request.user.id}_{request.user.is_superuser}'
        cached_data = cache.get(cache_key)
        
        if cached_data and not request.GET.get('refresh'):
            return Response(cached_data)
        
        # Generate fresh data
        data = self._generate_dashboard_data(request)
        
        # Cache the result
        cache.set(cache_key, data, CACHE_TTL)
        
        return Response(data)
    
    def _generate_dashboard_data(self, request):
        """Generate dashboard data with optimized queries"""
        now = timezone.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        # Use select_related and prefetch_related for optimization
        alerts_qs = SecurityAlert.objects.select_related(
            'user', 'acknowledged_by', 'resolved_by'
        )
        
        # If not superuser, filter to user's own data
        if not request.user.is_superuser:
            alerts_qs = alerts_qs.filter(
                Q(user=request.user) | Q(created_by=request.user)
            )
        
        # Batch aggregate queries
        alerts_stats = alerts_qs.aggregate(
            total_active=Count('id', filter=Q(
                status__in=['new', 'acknowledged', 'investigating']
            )),
            critical=Count('id', filter=Q(status='new', severity='critical')),
            high=Count('id', filter=Q(status='new', severity='high')),
            last_24h=Count('id', filter=Q(created_at__gte=last_24h)),
        )
        
        # Optimize failed login queries
        failed_login_stats = AuditLog.objects.filter(
            action='login_failed'
        ).aggregate(
            last_hour=Count('id', filter=Q(
                timestamp__gte=now - timedelta(hours=1)
            )),
            last_24h=Count('id', filter=Q(timestamp__gte=last_24h)),
            unique_ips_24h=Count('ip_address', distinct=True, filter=Q(
                timestamp__gte=last_24h
            )),
        )
        
        # Session statistics with optimization
        session_stats = SessionMonitor.objects.aggregate(
            total_active=Count('id', filter=Q(
                terminated=False, expires_at__gt=now
            )),
            suspicious=Count('id', filter=Q(
                terminated=False, is_suspicious=True
            )),
        )
        
        # IP blacklist stats
        blacklist_stats = IPBlacklist.objects.aggregate(
            total=Count('id', filter=Q(is_active=True)),
            last_24h=Count('id', filter=Q(blocked_at__gte=last_24h)),
        )
        
        # User statistics - only for admins
        user_stats = {}
        if request.user.is_staff:
            from accounts.models import CustomUser
            user_stats = CustomUser.objects.aggregate(
                total=Count('id'),
                active_today=Count('id', filter=Q(
                    last_activity__date=now.date()
                )),
                pending_approval=Count('id', filter=Q(
                    approval_status='pending'
                )),
                without_mfa=Count('id', filter=Q(
                    is_active=True, mfa_enabled=False, is_superuser=False
                )),
            )
        
        # Recent alerts with pagination
        recent_alerts = alerts_qs.filter(
            created_at__gte=last_24h
        ).order_by('-created_at')[:10]
        
        # Performance metrics with error handling
        try:
            perf_metrics = PerformanceMetric.objects.filter(
                timestamp__gte=last_24h
            ).aggregate(
                avg_response_time=Avg('value', filter=Q(
                    metric_type='response_time'
                )),
                total_requests=Count('id', filter=Q(
                    metric_type='response_time'
                )),
                error_count=Count('id', filter=Q(
                    metric_type='error_rate'
                )),
            )
            
            error_rate = 0
            if perf_metrics['total_requests'] > 0:
                error_rate = (perf_metrics['error_count'] / perf_metrics['total_requests']) * 100
            
            performance = {
                'avg_response_time': round(perf_metrics['avg_response_time'] or 0, 2),
                'error_rate': round(error_rate, 2),
                'total_requests_24h': perf_metrics['total_requests'],
            }
        except Exception as e:
            logger.error(f"Error calculating performance metrics: {e}")
            performance = {
                'avg_response_time': 0,
                'error_rate': 0,
                'total_requests_24h': 0,
            }
        
        # Optimize timeline generation with single query
        timeline_data = self._generate_timeline_data(last_7d, now)
        
        # Mask sensitive data
        masked_user_stats = {}
        if user_stats:
            masked_user_stats = {
                'total': user_stats['total'],
                'active_today': user_stats['active_today'],
                'pending_approval': user_stats['pending_approval'],
                'without_mfa': user_stats['without_mfa'],
            }
        
        data = {
            'alerts_summary': alerts_stats,
            'failed_logins': failed_login_stats,
            'sessions': session_stats,
            'blocked_ips': blacklist_stats,
            'users': masked_user_stats,
            'recent_alerts': SecurityAlertSerializer(recent_alerts, many=True).data,
            'performance': performance,
            'timeline': timeline_data,
        }
        
        return data
    
    def _generate_timeline_data(self, start_date, end_date):
        """Generate timeline data with optimized queries"""
        # Single query for all audit logs
        audit_logs = AuditLog.objects.filter(
            timestamp__range=[start_date, end_date]
        ).values('timestamp__date', 'action').annotate(
            count=Count('id')
        )
        
        # Single query for alerts
        alerts = SecurityAlert.objects.filter(
            created_at__range=[start_date, end_date]
        ).values('created_at__date').annotate(
            count=Count('id')
        )
        
        # Process data into timeline format
        timeline_dict = {}
        for i in range(7):
            date = (end_date - timedelta(days=i)).date()
            timeline_dict[date] = {
                'date': date.isoformat(),
                'logins': 0,
                'failed_logins': 0,
                'alerts': 0,
            }
        
        # Populate from aggregated data
        for log in audit_logs:
            date = log['timestamp__date']
            if date in timeline_dict:
                if log['action'] == 'login':
                    timeline_dict[date]['logins'] = log['count']
                elif log['action'] == 'login_failed':
                    timeline_dict[date]['failed_logins'] = log['count']
        
        for alert in alerts:
            date = alert['created_at__date']
            if date in timeline_dict:
                timeline_dict[date]['alerts'] = alert['count']
        
        return list(timeline_dict.values())


class SecurityMetricsView(APIView):
    """Get detailed security metrics with proper validation"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    
    @ratelimit(key='user', rate='20/m', method='GET')
    def get(self, request):
        # Validate period parameter
        period = request.query_params.get('period', '24h')
        valid_periods = ['1h', '24h', '7d', '30d']
        
        if period not in valid_periods:
            return Response(
                {'error': _('Invalid period. Must be one of: %(periods)s') % {
                    'periods': ', '.join(valid_periods)
                }},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Calculate time range with max limit
        now = timezone.now()
        period_map = {
            '1h': timedelta(hours=1),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30),
        }
        start_time = now - period_map[period]
        
        # Try cache first
        cache_key = f'security_metrics_{request.user.id}_{period}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data)
        
        # Generate metrics
        data = self._generate_metrics(start_time, now, period)
        
        # Cache results
        cache.set(cache_key, data, 60)  # 1 minute cache for metrics
        
        return Response(data)
    
    def _generate_metrics(self, start_time, end_time, period):
        """Generate security metrics with optimized queries"""
        # Batch aggregate queries
        threat_metrics = {
            'brute_force_attempts': AuditLog.objects.filter(
                action='login_failed',
                timestamp__range=[start_time, end_time]
            ).values('ip_address').annotate(
                attempts=Count('id')
            ).filter(attempts__gte=5).count(),
            
            'suspicious_activities': SecurityAlert.objects.filter(
                alert_type='suspicious_activity',
                created_at__range=[start_time, end_time]
            ).count(),
            
            'blocked_threats': IPBlacklist.objects.filter(
                blocked_at__range=[start_time, end_time]
            ).count(),
        }
        
        # Authentication metrics with single query
        auth_stats = AuditLog.objects.filter(
            action__in=['login', 'login_failed', 'mfa_failed'],
            timestamp__range=[start_time, end_time]
        ).values('action').annotate(count=Count('id'))
        
        auth_metrics = {
            'total_logins': 0,
            'failed_logins': 0,
            'mfa_failures': 0,
            'success_rate': 0,
        }
        
        for stat in auth_stats:
            if stat['action'] == 'login':
                auth_metrics['total_logins'] = stat['count']
            elif stat['action'] == 'login_failed':
                auth_metrics['failed_logins'] = stat['count']
            elif stat['action'] == 'mfa_failed':
                auth_metrics['mfa_failures'] = stat['count']
        
        total_attempts = auth_metrics['total_logins'] + auth_metrics['failed_logins']
        if total_attempts > 0:
            auth_metrics['success_rate'] = round(
                (auth_metrics['total_logins'] / total_attempts) * 100, 2
            )
        
        # Top threats with limit
        top_threat_ips = list(AuditLog.objects.filter(
            action__in=['login_failed', 'unauthorized_access'],
            timestamp__range=[start_time, end_time]
        ).values('ip_address').annotate(
            threat_score=Count('id')
        ).order_by('-threat_score')[:10])
        
        # Alert distribution
        alert_distribution = list(SecurityAlert.objects.filter(
            created_at__range=[start_time, end_time]
        ).values('alert_type').annotate(
            count=Count('id')
        ).order_by('-count'))
        
        return {
            'period': period,
            'threat_metrics': threat_metrics,
            'auth_metrics': auth_metrics,
            'top_threat_ips': top_threat_ips,
            'alert_distribution': alert_distribution,
        }


class AlertListView(generics.ListAPIView):
    """List security alerts with filtering and pagination"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    serializer_class = SecurityAlertSerializer
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        queryset = SecurityAlert.objects.select_related(
            'user', 'acknowledged_by', 'resolved_by'
        ).prefetch_related('child_alerts')
        
        # Filter by user if not admin
        if not self.request.user.is_staff:
            queryset = queryset.filter(
                Q(user=self.request.user) | Q(created_by=self.request.user)
            )
        
        # Apply filters
        severity = self.request.query_params.get('severity')
        if severity and severity in dict(SecurityAlert.SEVERITY_CHOICES):
            queryset = queryset.filter(severity=severity)
        
        status = self.request.query_params.get('status')
        if status and status in dict(SecurityAlert.STATUS_CHOICES):
            queryset = queryset.filter(status=status)
        
        alert_type = self.request.query_params.get('type')
        if alert_type and alert_type in dict(SecurityAlert.ALERT_TYPE_CHOICES):
            queryset = queryset.filter(alert_type=alert_type)
        
        user_id = self.request.query_params.get('user_id')
        if user_id and self.request.user.is_staff:
            queryset = queryset.filter(user_id=user_id)
        
        # Date range validation
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date and end_date:
            try:
                # Validate date range
                from datetime import datetime
                start = datetime.fromisoformat(start_date)
                end = datetime.fromisoformat(end_date)
                
                # Limit date range to prevent DoS
                if (end - start).days > MAX_QUERY_DAYS:
                    raise ValueError(f"Date range cannot exceed {MAX_QUERY_DAYS} days")
                
                queryset = queryset.filter(created_at__date__range=[start_date, end_date])
            except (ValueError, TypeError) as e:
                # Log invalid date format attempts
                logger.warning(f"Invalid date format in query: {e}")
        
        return queryset.order_by('-created_at')


class AlertDetailView(generics.RetrieveUpdateAPIView):
    """Get and update security alert with object-level permissions"""
    permission_classes = [permissions.IsAuthenticated, IsAlertOwner]
    serializer_class = SecurityAlertSerializer
    queryset = SecurityAlert.objects.select_related(
        'user', 'acknowledged_by', 'resolved_by'
    )
    
    @audit_log_decorator('data_viewed', 'info')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @audit_log_decorator('data_updated', 'warning')
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)


class AcknowledgeAlertView(APIView):
    """Acknowledge a security alert with atomic operations"""
    permission_classes = [permissions.IsAuthenticated, IsAlertOwner]
    
    @ratelimit(key='user', rate='30/m', method='POST')
    @transaction.atomic
    @audit_log_decorator('alert_acknowledged', 'info')
    def post(self, request, pk):
        try:
            # Use select_for_update to prevent race conditions
            alert = SecurityAlert.objects.select_for_update().get(pk=pk)
            
            # Check permissions
            self.check_object_permissions(request, alert)
            
            if alert.status != 'new':
                return Response(
                    {'error': _('Alert already acknowledged')},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            alert.acknowledge(request.user)
            
            return Response(SecurityAlertSerializer(alert).data)
            
        except SecurityAlert.DoesNotExist:
            return Response(
                {'error': _('Alert not found')},
                status=status.HTTP_404_NOT_FOUND
            )


class ResolveAlertView(APIView):
    """Resolve a security alert with validation"""
    permission_classes = [permissions.IsAuthenticated, IsAlertOwner]
    
    @ratelimit(key='user', rate='30/m', method='POST')
    @transaction.atomic
    @audit_log_decorator('alert_resolved', 'info')
    def post(self, request, pk):
        try:
            alert = SecurityAlert.objects.select_for_update().get(pk=pk)
            
            # Check permissions
            self.check_object_permissions(request, alert)
            
            if alert.status == 'resolved':
                return Response(
                    {'error': _('Alert already resolved')},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            notes = request.data.get('notes', '')
            
            # Validate notes for high severity alerts
            if alert.severity in ['critical', 'high'] and not notes:
                return Response(
                    {'error': _('Resolution notes required for high severity alerts')},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            alert.resolve(request.user, notes)
            
            return Response(SecurityAlertSerializer(alert).data)
            
        except SecurityAlert.DoesNotExist:
            return Response(
                {'error': _('Alert not found')},
                status=status.HTTP_404_NOT_FOUND
            )


class IPBlacklistView(generics.ListAPIView):
    """List blacklisted IPs with pagination"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    serializer_class = IPBlacklistSerializer
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        queryset = IPBlacklist.objects.select_related(
            'blocked_by', 'unblocked_by'
        )
        
        # Filter by active status
        active_only = self.request.query_params.get('active', 'true')
        if active_only.lower() == 'true':
            queryset = queryset.filter(is_active=True)
        
        # Filter by reason
        reason = self.request.query_params.get('reason')
        if reason and reason in dict(IPBlacklist.REASON_CHOICES):
            queryset = queryset.filter(reason=reason)
        
        return queryset.order_by('-blocked_at')


class AddIPBlacklistView(APIView):
    """Add IP to blacklist with validation"""
    permission_classes = [permissions.IsAuthenticated, CanManageBlacklist]
    
    @ratelimit(key='user', rate='10/m', method='POST')
    @transaction.atomic
    @audit_log_decorator('ip_blocked', 'warning')
    def post(self, request):
        serializer = IPBlacklistSerializer(data=request.data)
        
        if serializer.is_valid():
            ip_address = serializer.validated_data['ip_address']
            
            # Check if already blacklisted
            if IPBlacklist.objects.filter(
                ip_address=ip_address,
                is_active=True
            ).exists():
                return Response(
                    {'error': _('IP already blacklisted')},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Create blacklist entry
            blacklist = serializer.save(blocked_by=request.user)
            
            # Create security alert
            SecurityAlert.objects.create(
                alert_type='ip_blocked',
                severity='medium',
                title=f'IP address blacklisted: {ip_address}',
                description=f'IP {ip_address} was manually blacklisted by {mask_email(request.user.email)}',
                ip_address=ip_address,
                details={
                    'reason': blacklist.reason,
                    'blocked_by': mask_email(request.user.email)
                }
            )
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RemoveIPBlacklistView(APIView):
    """Remove IP from blacklist"""
    permission_classes = [permissions.IsAuthenticated, CanManageBlacklist]
    
    @ratelimit(key='user', rate='10/m', method='POST')
    @transaction.atomic
    @audit_log_decorator('ip_unblocked', 'info')
    def post(self, request, pk):
        try:
            blacklist = IPBlacklist.objects.select_for_update().get(pk=pk)
            
            if not blacklist.is_active:
                return Response(
                    {'error': _('IP already unblocked')},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            blacklist.unblock(request.user)
            
            return Response({'message': _('IP unblocked successfully')})
            
        except IPBlacklist.DoesNotExist:
            return Response(
                {'error': _('Blacklist entry not found')},
                status=status.HTTP_404_NOT_FOUND
            )


class SessionMonitorListView(generics.ListAPIView):
    """List active sessions with filtering"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    serializer_class = SessionMonitorSerializer
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        queryset = SessionMonitor.objects.select_related('user', 'terminated_by').filter(
            terminated=False
        )
        
        # Filter by user for non-admins
        if not self.request.user.is_staff:
            queryset = queryset.filter(user=self.request.user)
        
        # Filter by specific user (admin only)
        user_id = self.request.query_params.get('user_id')
        if user_id and self.request.user.is_staff:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by suspicious
        suspicious_only = self.request.query_params.get('suspicious')
        if suspicious_only and suspicious_only.lower() == 'true':
            queryset = queryset.filter(is_suspicious=True)
        
        # Exclude expired
        queryset = queryset.filter(expires_at__gt=timezone.now())
        
        return queryset.order_by('-last_activity')


class SessionMonitorDetailView(generics.RetrieveAPIView):
    """Get session details with permissions"""
    permission_classes = [permissions.IsAuthenticated, IsSessionOwner]
    serializer_class = SessionMonitorSerializer
    queryset = SessionMonitor.objects.select_related('user', 'terminated_by')
    
    @audit_log_decorator('data_viewed', 'info')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class TerminateMonitoredSessionView(APIView):
    """Terminate a monitored session with proper cleanup"""
    permission_classes = [permissions.IsAuthenticated, IsSessionOwner]
    
    @ratelimit(key='user', rate='5/m', method='POST')
    @transaction.atomic
    @audit_log_decorator('session_terminated', 'warning')
    def post(self, request, pk):
        try:
            session = SessionMonitor.objects.select_for_update().get(pk=pk)
            
            # Check permissions
            self.check_object_permissions(request, session)
            
            if session.terminated:
                return Response(
                    {'error': _('Session already terminated')},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            reason = request.data.get('reason', 'Admin terminated')
            session.terminate(request.user, reason)
            
            # Invalidate Django session
            from django.contrib.sessions.models import Session
            try:
                django_session = Session.objects.get(session_key=session.session_key)
                django_session.delete()
            except Session.DoesNotExist:
                logger.warning(f"Django session not found: {session.session_key}")
            
            # Clear cache for this user
            cache_keys = [
                f'dashboard_data_{session.user.id}_*',
                f'security_metrics_{session.user.id}_*'
            ]
            for pattern in cache_keys:
                cache.delete_many(cache.keys(pattern))
            
            # Create security alert
            SecurityAlert.objects.create(
                alert_type='session_hijack',
                severity='medium',
                title=f'Session terminated for {mask_email(session.user.email)}',
                description=f'Admin {mask_email(request.user.email)} terminated session',
                user=session.user,
                ip_address=session.ip_address,
                details={
                    'session_id': str(session.id),
                    'reason': reason,
                    'terminated_by': mask_email(request.user.email)
                }
            )
            
            return Response({'message': _('Session terminated successfully')})
            
        except SessionMonitor.DoesNotExist:
            return Response(
                {'error': _('Session not found')},
                status=status.HTTP_404_NOT_FOUND
            )


class SecurityConfigView(generics.RetrieveAPIView):
    """Get current security configuration with caching"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    serializer_class = SecurityConfigSerializer
    
    def get_object(self):
        # Try cache first
        config = cache.get('active_security_config')
        if not config:
            config = SecurityConfiguration.get_active_config()
            cache.set('active_security_config', config, 3600)  # 1 hour
        return config


class UpdateSecurityConfigView(generics.UpdateAPIView):
    """Update security configuration with validation"""
    permission_classes = [permissions.IsAuthenticated, CanModifySecurityConfig]
    serializer_class = SecurityConfigSerializer
    
    def get_object(self):
        return SecurityConfiguration.get_active_config()
    
    @transaction.atomic
    @audit_log_decorator('config_changed', 'warning')
    def update(self, request, *args, **kwargs):
        # Clear config cache
        cache.delete('active_security_config')
        
        # Validate critical settings
        data = request.data
        
        # Ensure minimum security standards
        if 'min_password_length' in data and data['min_password_length'] < 8:
            return Response(
                {'error': _('Minimum password length cannot be less than 8')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if 'lockout_duration_minutes' in data and data['lockout_duration_minutes'] < 5:
            return Response(
                {'error': _('Lockout duration must be at least 5 minutes')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        response = super().update(request, *args, **kwargs)
        
        # Update the instance to track who made changes
        config = self.get_object()
        config.updated_by = request.user
        config.save(update_fields=['updated_by'])
        
        return response


class ThreatIntelligenceListView(generics.ListCreateAPIView):
    """List and create threat intelligence entries with pagination"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    serializer_class = ThreatIntelligenceSerializer
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        queryset = ThreatIntelligence.objects.all()
        
        # Filter by active
        active_only = self.request.query_params.get('active', 'true')
        if active_only.lower() == 'true':
            queryset = queryset.filter(is_active=True)
        
        # Filter by threat type
        threat_type = self.request.query_params.get('type')
        if threat_type and threat_type in dict(ThreatIntelligence.THREAT_TYPE_CHOICES):
            queryset = queryset.filter(threat_type=threat_type)
        
        # Filter by threat level
        threat_level = self.request.query_params.get('level')
        if threat_level and threat_level in dict(ThreatIntelligence.THREAT_LEVEL_CHOICES):
            queryset = queryset.filter(threat_level=threat_level)
        
        return queryset.order_by('-last_seen')
    
    @audit_log_decorator('data_created', 'warning')
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)


class ThreatIntelligenceDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Get, update, or delete threat intelligence with permissions"""
    permission_classes = [permissions.IsAuthenticated, CanManageBlacklist]
    serializer_class = ThreatIntelligenceSerializer
    queryset = ThreatIntelligence.objects.all()
    
    @audit_log_decorator('data_viewed', 'info')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @audit_log_decorator('data_updated', 'warning')
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)
    
    @audit_log_decorator('data_deleted', 'warning')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class SecurityReportsView(APIView):
    """Generate security reports with validation and limits"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    
    @ratelimit(key='user', rate='10/h', method='GET')
    def get(self, request):
        report_type = request.query_params.get('type', 'summary')
        period = request.query_params.get('period', '7d')
        
        # Validate report type
        valid_types = ['summary', 'threats', 'compliance']
        if report_type not in valid_types:
            return Response(
                {'error': _('Invalid report type. Must be one of: %(types)s') % {
                    'types': ', '.join(valid_types)
                }},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate and parse period
        valid_periods = ['24h', '7d', '30d']
        if period not in valid_periods:
            return Response(
                {'error': _('Invalid period. Must be one of: %(periods)s') % {
                    'periods': ', '.join(valid_periods)
                }},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Determine time range
        now = timezone.now()
        period_map = {
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30),
        }
        start_date = now - period_map[period]
        
        # Check cache
        cache_key = f'security_report_{request.user.id}_{report_type}_{period}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data)
        
        # Generate report based on type
        if report_type == 'summary':
            data = self._generate_summary_report(start_date, now)
        elif report_type == 'threats':
            data = self._generate_threat_report(start_date, now)
        else:  # compliance
            data = self._generate_compliance_report(start_date, now)
        
        # Cache the report
        cache.set(cache_key, data, 300)  # 5 minutes
        
        return Response(data)
    
    def _generate_summary_report(self, start_date, end_date):
        """Generate summary security report with optimized queries"""
        # Use aggregation for better performance
        alert_stats = SecurityAlert.objects.filter(
            created_at__range=[start_date, end_date]
        ).aggregate(
            total=Count('id'),
            resolved=Count('id', filter=Q(status='resolved')),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high')),
        )
        
        return {
            'report_type': 'summary',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'summary': {
                'total_alerts': alert_stats['total'],
                'resolved_alerts': alert_stats['resolved'],
                'critical_alerts': alert_stats['critical'],
                'high_alerts': alert_stats['high'],
                'blocked_ips': IPBlacklist.objects.filter(
                    blocked_at__range=[start_date, end_date]
                ).count(),
                'terminated_sessions': SessionMonitor.objects.filter(
                    terminated_at__range=[start_date, end_date]
                ).count(),
            }
        }
    
    def _generate_threat_report(self, start_date, end_date):
        """Generate threat analysis report"""
        threat_summary = SecurityAlert.objects.filter(
            created_at__range=[start_date, end_date]
        ).values('alert_type').annotate(
            count=Count('id'),
            critical=Count('id', filter=Q(severity='critical')),
            high=Count('id', filter=Q(severity='high'))
        ).order_by('-count')[:20]  # Limit results
        
        return {
            'report_type': 'threats',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'threats': list(threat_summary)
        }
    
    def _generate_compliance_report(self, start_date, end_date):
        """Generate compliance report"""
        from audit_trail.models import ComplianceLog
        
        compliance_summary = ComplianceLog.objects.filter(
            timestamp__range=[start_date, end_date]
        ).values('compliance_type').annotate(
            total=Count('id'),
            completed=Count('id', filter=Q(status='completed'))
        )
        
        return {
            'report_type': 'compliance',
            'period': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            },
            'compliance': list(compliance_summary)
        }


class GenerateSecurityReportView(APIView):
    """Generate and queue security report with rate limiting"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    
    @ratelimit(key='user', rate='5/h', method='POST')
    @audit_log_decorator('data_exported', 'info')
    def post(self, request):
        report_type = request.data.get('type', 'summary')
        period_days = request.data.get('days', 7)
        
        # Validate inputs
        valid_types = ['summary', 'threats', 'compliance']
        if report_type not in valid_types:
            return Response(
                {'error': _('Invalid report type')},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            period_days = int(period_days)
            if period_days < 1 or period_days > MAX_QUERY_DAYS:
                raise ValueError
        except (ValueError, TypeError):
            return Response(
                {'error': _('Invalid period. Must be between 1 and %(max)d days') % {
                    'max': MAX_QUERY_DAYS
                }},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Queue report generation task
        from .tasks import generate_security_report_task
        task = generate_security_report_task.delay(
            report_type=report_type,
            period_days=period_days,
            user_id=str(request.user.id)
        )
        
        return Response({
            'message': _('Report generation queued'),
            'task_id': task.id
        }, status=status.HTTP_202_ACCEPTED)


class DownloadSecurityReportView(APIView):
    """Download generated security report with streaming"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    
    @audit_log_decorator('data_exported', 'info')
    def get(self, request, pk):
        """Stream CSV report to prevent memory issues with large datasets"""
        
        def generate_csv_rows():
            """Generator for CSV rows"""
            # Header
            yield ['Security Report', timezone.now().strftime('%Y-%m-%d %H:%M:%S')]
            yield []
            yield ['Metric', 'Value', 'Details']
            
            # Get report data with limits
            alerts = SecurityAlert.objects.filter(
                created_at__gte=timezone.now() - timedelta(days=30)
            ).select_related('user')[:MAX_EXPORT_RECORDS]
            
            yield ['Total Alerts', alerts.count(), '']
            yield ['Active Alerts', alerts.filter(status='new').count(), '']
            
            # Alert details
            yield []
            yield ['Alert Details']
            yield ['ID', 'Type', 'Severity', 'Status', 'Created', 'User']
            
            for alert in alerts:
                yield [
                    str(alert.id),
                    alert.get_alert_type_display(),
                    alert.get_severity_display(),
                    alert.get_status_display(),
                    alert.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    mask_email(alert.user.email) if alert.user else 'System'
                ]
            
            # IP Blacklist summary
            yield []
            yield ['Blocked IPs']
            blocked_ips = IPBlacklist.objects.filter(
                is_active=True
            ).select_related('blocked_by')[:100]
            
            yield ['Total Blocked IPs', blocked_ips.count(), '']
            yield []
            yield ['IP Address', 'Reason', 'Blocked At', 'Blocked By']
            
            for ip in blocked_ips:
                yield [
                    ip.ip_address,
                    ip.get_reason_display(),
                    ip.blocked_at.strftime('%Y-%m-%d %H:%M:%S'),
                    mask_email(ip.blocked_by.email) if ip.blocked_by else 'System'
                ]
        
        # Create streaming response
        response = StreamingHttpResponse(
            (csv.writer(StringIO()).writerow(row).encode('utf-8') for row in generate_csv_rows()),
            content_type='text/csv'
        )
        response['Content-Disposition'] = f'attachment; filename="security_report_{pk}.csv"'
        
        return response


class RealTimeMonitoringView(APIView):
    """Real-time monitoring endpoint with caching"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    
    @ratelimit(key='user', rate='60/m', method='GET')
    def get(self, request):
        # Check cache first
        cache_key = 'realtime_monitoring_data'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return Response(cached_data)
        
        # Get real-time metrics
        now = timezone.now()
        last_minute = now - timedelta(minutes=1)
        
        # Use aggregation for performance
        metrics = {
            'timestamp': now.isoformat(),
            'active_users': SessionMonitor.objects.filter(
                terminated=False,
                last_activity__gte=last_minute
            ).count(),
            'requests_per_minute': PerformanceMetric.objects.filter(
                metric_type='response_time',
                timestamp__gte=last_minute
            ).count(),
            'active_alerts': SecurityAlert.objects.filter(
                status='new'
            ).count(),
            'system_status': self._check_system_status()
        }
        
        # Cache for 10 seconds
        cache.set(cache_key, metrics, 10)
        
        return Response(metrics)
    
    def _check_system_status(self):
        """Check system health status"""
        try:
            # Check database
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            
            # Check cache
            cache.set('health_check', 'ok', 10)
            if cache.get('health_check') != 'ok':
                return 'degraded'
            
            return 'operational'
        except Exception as e:
            logger.error(f"System health check failed: {e}")
            return 'error'


class SubscribeToAlertsView(APIView):
    """Subscribe to real-time alerts (WebSocket placeholder)"""
    permission_classes = [permissions.IsAuthenticated, CanViewSecurityData]
    
    @ratelimit(key='user', rate='5/m', method='POST')
    def post(self, request):
        # In production, implement WebSocket subscription
        # For now, return subscription confirmation
        
        subscription_id = str(timezone.now().timestamp())
        
        # Store subscription in cache
        cache.set(
            f'alert_subscription_{subscription_id}',
            {
                'user_id': request.user.id,
                'created_at': timezone.now().isoformat(),
                'filters': request.data.get('filters', {})
            },
            3600  # 1 hour TTL
        )
        
        return Response({
            'subscription_id': subscription_id,
            'channel': 'security_alerts',
            'status': 'subscribed',
            'expires_in': 3600
        })


# Enhanced error handlers with security logging
def custom_400(request, exception=None):
    """Custom 400 Bad Request handler with sanitization"""
    from django.shortcuts import render
    
    # Log the bad request
    client_ip, _ = get_client_ip(request)
    logger.warning(f"400 Bad Request from {client_ip}: {sanitize_path(request.path)}")
    
    context = {
        'error_code': 400,
        'error_title': _('Bad Request'),
        'error_message': _('The request could not be understood by the server.'),
    }
    return render(request, 'errors/error.html', context, status=400)


def custom_403(request, exception=None):
    """Custom 403 Forbidden handler with security logging"""
    from django.shortcuts import render
    
    # Log the forbidden access with sanitized path
    if hasattr(request, 'user') and request.user.is_authenticated:
        client_ip, _ = get_client_ip(request)
        AuditLog.log(
            action='unauthorized_access',
            user=request.user,
            severity='warning',
            message=f'403 Forbidden: {sanitize_path(request.path)}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            metadata={
                'path': sanitize_path(request.path),
                'method': request.method,
                'referer': request.META.get('HTTP_REFERER', '')
            }
        )
    
    context = {
        'error_code': 403,
        'error_title': _('Access Forbidden'),
        'error_message': _('You do not have permission to access this resource.'),
    }
    return render(request, 'errors/error.html', context, status=403)


def custom_404(request, exception=None):
    """Custom 404 Not Found handler"""
    from django.shortcuts import render
    
    # Log 404s for monitoring (potential scanning)
    client_ip, _ = get_client_ip(request)
    logger.info(f"404 Not Found from {client_ip}: {sanitize_path(request.path)}")
    
    # Check for scanning patterns
    suspicious_patterns = [
        'wp-admin', 'phpMyAdmin', '.php', 'admin.php',
        '.env', 'config', '.git', 'backup'
    ]
    
    path_lower = request.path.lower()
    if any(pattern in path_lower for pattern in suspicious_patterns):
        # Log as potential security threat
        AuditLog.log(
            action='suspicious_activity',
            severity='warning',
            message=f'Potential scanning attempt: {sanitize_path(request.path)}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            metadata={'path': sanitize_path(request.path)}
        )
    
    context = {
        'error_code': 404,
        'error_title': _('Page Not Found'),
        'error_message': _('The page you are looking for could not be found.'),
    }
    return render(request, 'errors/error.html', context, status=404)


def custom_500(request):
    """Custom 500 Internal Server Error handler"""
    from django.shortcuts import render
    
    # Log critical error
    client_ip, _ = get_client_ip(request)
    logger.error(f"500 Internal Server Error: {sanitize_path(request.path)} from {client_ip}")
    
    # Create security alert for 500 errors
    try:
        SecurityAlert.objects.create(
            alert_type='suspicious_activity',
            severity='high',
            title='500 Internal Server Error',
            description=f'Server error occurred at {sanitize_path(request.path)}',
            ip_address=client_ip,
            details={
                'path': sanitize_path(request.path),
                'method': request.method,
                'timestamp': timezone.now().isoformat()
            }
        )
    except Exception as e:
        logger.error(f"Failed to create alert for 500 error: {e}")
    
    context = {
        'error_code': 500,
        'error_title': _('Internal Server Error'),
        'error_message': _('An unexpected error occurred. Our team has been notified.'),
    }
    return render(request, 'errors/error.html', context, status=500)