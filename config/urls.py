"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from two_factor.urls import urlpatterns as tf_urls
from two_factor.admin import AdminSiteOTPRequired

# Replace default admin with OTP required admin
admin.site.__class__ = AdminSiteOTPRequired

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # Two-factor authentication
    path('account/', include(tf_urls)),
    
    # API endpoints
    path('api/auth/', include('accounts.urls')),
    path('api/line/', include('line_bot.urls')),
    path('api/security/', include('security_suite.urls')),
    path('api/audit/', include('audit_trail.urls')),
    
    # LINE webhook
    path('webhook/', include('line_bot.webhook_urls')),
    
    # Security dashboard (React SPA)
    path('dashboard/', include('security_suite.dashboard_urls')),
    
    # Prometheus metrics
    path('metrics/', include('django_prometheus.urls')),
    
    # Root redirect
    path('', RedirectView.as_view(url='/dashboard/', permanent=False)),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Custom error handlers
handler400 = 'security_suite.views.custom_400'
handler403 = 'security_suite.views.custom_403'
handler404 = 'security_suite.views.custom_404'
handler500 = 'security_suite.views.custom_500'