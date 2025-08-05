# audit_trail/middleware.py

import time
import json
import logging
from django.utils import timezone
from django.urls import resolve
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest, HttpResponse
from .models import AuditLog, PerformanceMetric
from ipware import get_client_ip

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """
    Middleware to automatically log certain requests and track performance metrics
    """
    
    # URLs to exclude from automatic logging
    EXCLUDED_PATHS = [
        '/static/',
        '/media/',
        '/health/',
        '/metrics/',
        '/api/auth/token/refresh/',
    ]
    
    # URLs that should always be logged
    ALWAYS_LOG_PATHS = [
        '/api/auth/login/',
        '/api/auth/logout/',
        '/api/auth/register/',
        '/api/security/',
        '/admin/',
        '/api/line/groups/',
        '/api/audit/',
    ]
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Skip if path is excluded
        if any(request.path.startswith(excluded) for excluded in self.EXCLUDED_PATHS):
            return self.get_response(request)
        
        # Start timing
        start_time = time.time()
        
        # Get client IP
        client_ip, is_routable = get_client_ip(request)
        
        # Store request data for logging
        request._audit_data = {
            'start_time': start_time,
            'client_ip': client_ip,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'method': request.method,
            'path': request.path,
            'view_name': None,
        }
        
        # Try to resolve view name
        try:
            resolver_match = resolve(request.path)
            request._audit_data['view_name'] = resolver_match.view_name
        except:
            pass
        
        # Process request
        response = self.get_response(request)
        
        # Calculate response time
        end_time = time.time()
        response_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Log if necessary
        self._log_request(request, response, response_time)
        
        # Track performance metrics
        self._track_performance(request, response, response_time)
        
        return response
    
    def _should_log(self, request, response):
        """Determine if this request should be logged"""
        
        # Always log certain paths
        if any(request.path.startswith(path) for path in self.ALWAYS_LOG_PATHS):
            return True
        
        # Log authentication failures
        if response.status_code in [401, 403]:
            return True
        
        # Log server errors
        if response.status_code >= 500:
            return True
        
        # Log if user is authenticated and performing sensitive actions
        if hasattr(request, 'user') and request.user.is_authenticated:
            if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                return True
        
        return False
    
    def _log_request(self, request, response, response_time):
        """Log the request if necessary"""
        
        if not self._should_log(request, response):
            return
        
        try:
            # Determine action based on view and method
            action = self._determine_action(request, response)
            
            # Determine severity
            severity = 'info'
            if response.status_code >= 500:
                severity = 'error'
            elif response.status_code >= 400:
                severity = 'warning'
            
            # Build message
            message = f"{request.method} {request.path} - {response.status_code}"
            
            # Get user
            user = None
            if hasattr(request, 'user') and not isinstance(request.user, AnonymousUser):
                user = request.user
            
            # Metadata
            metadata = {
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'response_time_ms': round(response_time, 2),
                'view_name': request._audit_data.get('view_name'),
            }
            
            # Log to database
            AuditLog.log(
                action=action,
                user=user,
                severity=severity,
                message=message,
                ip_address=request._audit_data['client_ip'],
                user_agent=request._audit_data['user_agent'],
                session_key=request.session.session_key if hasattr(request, 'session') else '',
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
    
    def _determine_action(self, request, response):
        """Determine the audit action based on request and response"""
        
        view_name = request._audit_data.get('view_name', '')
        
        # Authentication actions
        if 'login' in view_name:
            return 'login' if response.status_code == 200 else 'login_failed'
        elif 'logout' in view_name:
            return 'logout'
        elif 'register' in view_name:
            return 'user_created'
        
        # User management
        elif 'approve_user' in view_name:
            return 'user_approved'
        elif 'reject_user' in view_name:
            return 'user_rejected'
        elif 'suspend_user' in view_name:
            return 'user_suspended'
        
        # Group management
        elif 'group' in view_name:
            if request.method == 'POST':
                return 'group_created'
            elif request.method in ['PUT', 'PATCH']:
                return 'group_updated'
            elif request.method == 'DELETE':
                return 'group_deleted'
        
        # Command execution
        elif 'command' in view_name or 'execution' in view_name:
            return 'command_executed' if response.status_code == 200 else 'command_failed'
        
        # Security events
        elif 'security' in view_name or 'alert' in view_name:
            return 'security_alert'
        elif 'ip_blacklist' in view_name:
            return 'ip_blocked' if request.method == 'POST' else 'ip_unblocked'
        
        # Data operations
        elif request.method == 'GET' and 'detail' in view_name:
            return 'data_viewed'
        elif request.method in ['POST', 'PUT', 'PATCH']:
            return 'data_modified'
        elif request.method == 'DELETE':
            return 'data_deleted'
        
        # Default
        return 'data_viewed'
    
    def _track_performance(self, request, response, response_time):
        """Track performance metrics"""
        
        try:
            # Only track API endpoints
            if not request.path.startswith('/api/'):
                return
            
            # Create performance metric
            PerformanceMetric.objects.create(
                metric_type='response_time',
                value=response_time,
                unit='ms',
                endpoint=request.path,
                metadata={
                    'method': request.method,
                    'status_code': response.status_code,
                    'view_name': request._audit_data.get('view_name'),
                }
            )
            
            # Track error rate
            if response.status_code >= 400:
                PerformanceMetric.objects.create(
                    metric_type='error_rate',
                    value=1,
                    unit='count',
                    endpoint=request.path,
                    metadata={
                        'method': request.method,
                        'status_code': response.status_code,
                        'error_type': 'client_error' if response.status_code < 500 else 'server_error',
                    }
                )
            
        except Exception as e:
            logger.error(f"Failed to track performance metric: {str(e)}")
    
    def process_exception(self, request, exception):
        """Log exceptions"""
        
        try:
            # Log the exception
            AuditLog.log(
                action='data_viewed',  # Generic action for exceptions
                user=request.user if hasattr(request, 'user') and not isinstance(request.user, AnonymousUser) else None,
                severity='error',
                message=f"Exception in {request.method} {request.path}: {str(exception)}",
                ip_address=request._audit_data.get('client_ip'),
                user_agent=request._audit_data.get('user_agent'),
                metadata={
                    'exception_type': type(exception).__name__,
                    'exception_message': str(exception),
                    'method': request.method,
                    'path': request.path,
                }
            )
        except Exception as e:
            logger.error(f"Failed to log exception: {str(e)}")
        
        return None