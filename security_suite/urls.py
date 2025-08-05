from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'security_suite'

# Create a router for ViewSets (if we add any in the future)
router = DefaultRouter()

urlpatterns = [
    # Dashboard Data API
    path('dashboard/data/', views.DashboardDataView.as_view(), name='dashboard_data'),
    path('dashboard/metrics/', views.SecurityMetricsView.as_view(), name='security_metrics'),
    
    # Security Alerts - RESTful endpoints
    path('alerts/', views.AlertListView.as_view(), name='alert_list'),
    path('alerts/<uuid:pk>/', views.AlertDetailView.as_view(), name='alert_detail'),
    path('alerts/<uuid:pk>/acknowledge/', views.AcknowledgeAlertView.as_view(), name='acknowledge_alert'),
    path('alerts/<uuid:pk>/resolve/', views.ResolveAlertView.as_view(), name='resolve_alert'),
    
    # IP Management - RESTful endpoints
    path('ip-blacklist/', views.IPBlacklistView.as_view(), name='ip_blacklist_list'),
    path('ip-blacklist/add/', views.AddIPBlacklistView.as_view(), name='ip_blacklist_create'),
    path('ip-blacklist/<uuid:pk>/remove/', views.RemoveIPBlacklistView.as_view(), name='ip_blacklist_remove'),
    
    # Session Monitoring - RESTful endpoints
    path('sessions/', views.SessionMonitorListView.as_view(), name='session_list'),
    path('sessions/<uuid:pk>/', views.SessionMonitorDetailView.as_view(), name='session_detail'),
    path('sessions/<uuid:pk>/terminate/', views.TerminateMonitoredSessionView.as_view(), name='session_terminate'),
    
    # Security Configuration
    path('config/', views.SecurityConfigView.as_view(), name='security_config_detail'),
    path('config/update/', views.UpdateSecurityConfigView.as_view(), name='security_config_update'),
    
    # Threat Intelligence - RESTful endpoints
    path('threats/', views.ThreatIntelligenceListView.as_view(), name='threat_list'),
    path('threats/add/', views.ThreatIntelligenceListView.as_view(), name='threat_create'),  # POST to same view
    path('threats/<uuid:pk>/', views.ThreatIntelligenceDetailView.as_view(), name='threat_detail'),
    path('threats/<uuid:pk>/update/', views.ThreatIntelligenceDetailView.as_view(), name='threat_update'),  # PUT/PATCH
    
    # Security Reports
    path('reports/', views.SecurityReportsView.as_view(), name='security_reports'),
    path('reports/generate/', views.GenerateSecurityReportView.as_view(), name='report_generate'),
    path('reports/<uuid:pk>/download/', views.DownloadSecurityReportView.as_view(), name='report_download'),
    
    # Real-time Monitoring
    path('realtime/', views.RealTimeMonitoringView.as_view(), name='realtime_monitoring'),
    path('realtime/subscribe/', views.SubscribeToAlertsView.as_view(), name='realtime_subscribe'),
    
    # Include router URLs
    path('', include(router.urls)),
]

# WebSocket URLs (for use with Django Channels if implemented)
websocket_urlpatterns = [
    # path('ws/alerts/', consumers.AlertConsumer.as_asgi()),
    # path('ws/monitoring/', consumers.MonitoringConsumer.as_asgi()),
]