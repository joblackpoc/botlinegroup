# audit_trail/urls.py

from django.urls import path
from . import views

app_name = 'audit_trail'

urlpatterns = [
    # Audit Logs
    path('logs/', views.AuditLogListView.as_view(), name='audit_log_list'),
    path('logs/<uuid:pk>/', views.AuditLogDetailView.as_view(), name='audit_log_detail'),
    path('logs/export/', views.ExportAuditLogsView.as_view(), name='export_audit_logs'),
    path('logs/search/', views.SearchAuditLogsView.as_view(), name='search_audit_logs'),
    
    # Data Access Logs
    path('data-access/', views.DataAccessLogListView.as_view(), name='data_access_list'),
    path('data-access/<uuid:pk>/', views.DataAccessLogDetailView.as_view(), name='data_access_detail'),
    path('data-access/report/', views.DataAccessReportView.as_view(), name='data_access_report'),
    
    # Compliance Logs
    path('compliance/', views.ComplianceLogListView.as_view(), name='compliance_list'),
    path('compliance/create/', views.CreateComplianceLogView.as_view(), name='create_compliance'),
    path('compliance/<uuid:pk>/', views.ComplianceLogDetailView.as_view(), name='compliance_detail'),
    path('compliance/<uuid:pk>/update/', views.UpdateComplianceLogView.as_view(), name='update_compliance'),
    
    # Performance Metrics
    path('metrics/', views.PerformanceMetricsView.as_view(), name='performance_metrics'),
    path('metrics/chart/', views.MetricsChartDataView.as_view(), name='metrics_chart_data'),
    path('metrics/export/', views.ExportMetricsView.as_view(), name='export_metrics'),
    
    # Activity Timeline
    path('timeline/', views.ActivityTimelineView.as_view(), name='activity_timeline'),
    path('timeline/user/<uuid:user_id>/', views.UserActivityTimelineView.as_view(), name='user_timeline'),
    
    # Audit Reports - Using the main AuditReportsView with different query params
    path('reports/', views.AuditReportsView.as_view(), name='audit_reports'),
    
    # Retention Management
    path('retention/', views.RetentionManagementView.as_view(), name='retention_management'),
    path('retention/cleanup/', views.CleanupOldLogsView.as_view(), name='cleanup_logs'),
]