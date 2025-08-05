# accounts/views_admin.py
# This should be appended to accounts/views.py
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.conf import settings
from ipware import get_client_ip
import pyotp
import uuid
from datetime import timedelta


from .models import CustomUser, PasswordHistory
from .serializers import (
    UserSerializer, LoginSerializer, RegisterSerializer,
    ChangePasswordSerializer, MFASetupSerializer, MFAVerifySerializer,
    UserProfileSerializer, UserListSerializer, ApprovalQueueSerializer,
    SessionSerializer
)
from .tasks import (
    send_approval_notification, send_new_user_notification_to_admins,
    send_mfa_setup_reminder
)
from audit_trail.models import AuditLog
from security_suite.models import SecurityAlert, SessionMonitor
from .permissions import IsAdminUser, IsSuperUser

class SuspendUserView(APIView):
    """Suspend user account"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
            
            if not user.is_active:
                return Response(
                    {'error': 'User is already suspended'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Suspend user
            user.suspend_user(request.user)
            
            # Terminate all active sessions
            SessionMonitor.objects.filter(
                user=user,
                terminated=False
            ).update(
                terminated=True,
                terminated_at=timezone.now(),
                terminated_by=request.user,
                termination_reason='Account suspended'
            )
            
            # Log suspension
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='user_suspended',
                user=request.user,
                severity='warning',
                message=f'User {user.email} suspended by {request.user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                content_object=user
            )
            
            # Create security alert
            SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='high',
                title=f'User account suspended: {user.email}',
                description=f'Account suspended by admin {request.user.email}',
                user=user,
                details={'suspended_by': request.user.email}
            )
            
            return Response({
                'message': 'User suspended successfully',
                'user': UserSerializer(user).data
            })
            
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ActivateUserView(APIView):
    """Reactivate suspended user account"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
            
            if user.is_active:
                return Response(
                    {'error': 'User is already active'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Activate user
            user.is_active = True
            user.approval_status = 'approved' if user.is_approved else 'pending'
            user.failed_login_attempts = 0
            user.save()
            
            # Log activation
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='user_activated',
                user=request.user,
                severity='info',
                message=f'User {user.email} activated by {request.user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                content_object=user
            )
            
            return Response({
                'message': 'User activated successfully',
                'user': UserSerializer(user).data
            })
            
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ActiveSessionsView(generics.ListAPIView):
    """View active sessions for current user or all (admin)"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SessionSerializer
    
    def get_queryset(self):
        user = self.request.user
        
        if user.is_admin:
            # Admins can see all sessions
            queryset = SessionMonitor.objects.filter(terminated=False)
            
            # Filter by user if specified
            user_id = self.request.query_params.get('user_id')
            if user_id:
                queryset = queryset.filter(user_id=user_id)
        else:
            # Regular users see only their sessions
            queryset = SessionMonitor.objects.filter(
                user=user,
                terminated=False
            )
        
        return queryset.order_by('-last_activity')


class TerminateSessionView(APIView):
    """Terminate a specific session"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, pk):
        try:
            session = SessionMonitor.objects.get(pk=pk)
            
            # Check permissions
            if not request.user.is_admin and session.user != request.user:
                return Response(
                    {'error': 'Permission denied'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Terminate session
            reason = request.data.get('reason', 'Manually terminated')
            session.terminate(request.user, reason)
            
            # Invalidate Django session
            from django.contrib.sessions.models import Session
            try:
                django_session = Session.objects.get(session_key=session.session_key)
                django_session.delete()
            except Session.DoesNotExist:
                pass
            
            # Log termination
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='session_terminated',
                user=request.user,
                severity='warning',
                message=f'Session terminated for user {session.user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                content_object=session,
                metadata={
                    'terminated_session_id': str(session.id),
                    'reason': reason
                }
            )
            
            return Response({'message': 'Session terminated successfully'})
            
        except SessionMonitor.DoesNotExist:
            return Response(
                {'error': 'Session not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class ApprovalQueueView(generics.ListAPIView):
    """List users pending approval"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = ApprovalQueueSerializer
    
    def get_queryset(self):
        return CustomUser.objects.filter(
            approval_status='pending'
        ).order_by('-date_joined')
    
    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        
        # Add summary statistics
        response.data['summary'] = {
            'total_pending': self.get_queryset().count(),
            'pending_today': self.get_queryset().filter(
                date_joined__date=timezone.now().date()
            ).count(),
            'pending_this_week': self.get_queryset().filter(
                date_joined__gte=timezone.now() - timedelta(days=7)
            ).count()
        }
        
        return response