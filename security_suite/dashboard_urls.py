from django.urls import path
from django.views.generic import TemplateView
from django.contrib.auth.decorators import login_required

app_name = 'dashboard'

urlpatterns = [
    # React SPA Dashboard
    path('', login_required(TemplateView.as_view(template_name='security/dashboard.html')), name='main'),
    path('<path:path>/', login_required(TemplateView.as_view(template_name='security/dashboard.html')), name='dashboard_spa'),
]