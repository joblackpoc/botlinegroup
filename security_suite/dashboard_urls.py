from django.urls import path, re_path
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import cache_page
from django.views.decorators.csrf import ensure_csrf_cookie
from .views import DashboardDataView, SecurityMetricsView
from .decorators import require_security_clearance
from django.conf import settings

app_name = 'dashboard'

# Cache duration for static assets
STATIC_CACHE_DURATION = 3600  # 1 hour

# Custom decorator to combine login and permission checks
def security_dashboard_required(view_func):
    """Decorator to ensure user has access to security dashboard"""
    decorated_view = login_required(view_func)
    decorated_view = require_security_clearance(decorated_view)
    decorated_view = ensure_csrf_cookie(decorated_view)
    return decorated_view

# Dashboard template view with security
class SecureDashboardView(TemplateView):
    template_name = 'security/dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'user': self.request.user,
            'is_admin': self.request.user.is_staff,
            'is_superuser': self.request.user.is_superuser,
            'api_endpoints': {
                'dashboard_data': '/api/security/dashboard/data/',
                'metrics': '/api/security/dashboard/metrics/',
                'alerts': '/api/security/alerts/',
                'sessions': '/api/security/sessions/',
                'realtime': '/api/security/realtime/',
            },
            'websocket_url': getattr(settings, 'WEBSOCKET_URL', '/ws/security/'),
            'refresh_interval': getattr(settings, 'DASHBOARD_REFRESH_INTERVAL', 30000),  # 30 seconds
        })
        return context

urlpatterns = [
    # Main dashboard - React SPA
    path(
        '', 
        security_dashboard_required(SecureDashboardView.as_view()), 
        name='main'
    ),
    
    # API endpoints specifically for dashboard
    path(
        'api/data/', 
        security_dashboard_required(DashboardDataView.as_view()), 
        name='api_data'
    ),
    path(
        'api/metrics/', 
        security_dashboard_required(SecurityMetricsView.as_view()), 
        name='api_metrics'
    ),
    
    # Static dashboard pages (cached)
    path(
        'alerts/', 
        cache_page(STATIC_CACHE_DURATION)(
            security_dashboard_required(
                TemplateView.as_view(template_name='security/dashboard.html')
            )
        ), 
        name='alerts'
    ),
    path(
        'sessions/', 
        cache_page(STATIC_CACHE_DURATION)(
            security_dashboard_required(
                TemplateView.as_view(template_name='security/dashboard.html')
            )
        ), 
        name='sessions'
    ),
    path(
        'threats/', 
        cache_page(STATIC_CACHE_DURATION)(
            security_dashboard_required(
                TemplateView.as_view(template_name='security/dashboard.html')
            )
        ), 
        name='threats'
    ),
    path(
        'reports/', 
        cache_page(STATIC_CACHE_DURATION)(
            security_dashboard_required(
                TemplateView.as_view(template_name='security/dashboard.html')
            )
        ), 
        name='reports'
    ),
    path(
        'config/', 
        security_dashboard_required(
            TemplateView.as_view(template_name='security/dashboard.html')
        ), 
        name='config'
    ),
    
    # Catch-all for React Router - must be last
    re_path(
        r'^(?P<path>.*)/$', 
        security_dashboard_required(
            TemplateView.as_view(template_name='security/dashboard.html')
        ), 
        name='dashboard_spa'
    ),
]

# WebSocket routing for dashboard (if using Django Channels)
websocket_urlpatterns = [
    # re_path(r'ws/security/dashboard/$', consumers.DashboardConsumer.as_asgi()),
]