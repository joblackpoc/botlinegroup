from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import webhook

app_name = 'webhook'

urlpatterns = [
    path('line/', csrf_exempt(webhook.LineWebhookView.as_view()), name='line_webhook'),
]