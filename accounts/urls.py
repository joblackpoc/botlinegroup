from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenBlacklistView,
)
from . import views

app_name = 'accounts'

urlpatterns = [
    # Authentication
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('register/', views.RegisterView.as_view(), name='register'),
    
    # JWT Token Management
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    
    # Password Management
    path('password/change/', views.ChangePasswordView.as_view(), name='change_password'),
    path('password/reset/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    # MFA Management
    path('mfa/setup/', views.MFASetupView.as_view(), name='mfa_setup'),
    path('mfa/verify/', views.MFAVerifyView.as_view(), name='mfa_verify'),
    path('mfa/disable/', views.MFADisableView.as_view(), name='mfa_disable'),
    path('mfa/backup-codes/', views.MFABackupCodesView.as_view(), name='mfa_backup_codes'),
    
    # User Profile
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('profile/update/', views.UpdateProfileView.as_view(), name='update_profile'),
    
    # User Management (Admin)
    path('users/', views.UserListView.as_view(), name='user_list'),
    path('users/<uuid:pk>/', views.UserDetailView.as_view(), name='user_detail'),
    path('users/<uuid:pk>/approve/', views.ApproveUserView.as_view(), name='approve_user'),
    path('users/<uuid:pk>/reject/', views.RejectUserView.as_view(), name='reject_user'),
    path('users/<uuid:pk>/suspend/', views.SuspendUserView.as_view(), name='suspend_user'),
    path('users/<uuid:pk>/activate/', views.ActivateUserView.as_view(), name='activate_user'),
    
    # Session Management
    path('sessions/', views.ActiveSessionsView.as_view(), name='active_sessions'),
    path('sessions/<uuid:pk>/terminate/', views.TerminateSessionView.as_view(), name='terminate_session'),
    
    # Approval Queue
    path('approval-queue/', views.ApprovalQueueView.as_view(), name='approval_queue'),
]