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


class CustomLoginView(TokenObtainPairView):
    """Enhanced login with MFA support"""
    serializer_class = LoginSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            # Log failed login attempt
            email = request.data.get('email', '')
            client_ip, _ = get_client_ip(request)
            
            AuditLog.log(
                action='login_failed',
                severity='warning',
                message=f'Failed login attempt for {email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                metadata={'error': str(e)}
            )
            
            # Check if we should create security alert
            self._check_failed_login_patterns(email, client_ip)
            
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Get user
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        mfa_token = serializer.validated_data.get('mfa_token')
        
        user = authenticate(request, username=email, password=password)
        
        if not user:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if user is approved
        if not user.is_approved and not user.is_superuser:
            return Response(
                {'error': 'Your account is pending approval'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check if account is locked
        if user.is_locked_out():
            return Response(
                {'error': 'Account is locked due to too many failed attempts'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Check MFA
        if user.mfa_enabled:
            if not mfa_token:
                return Response(
                    {'error': 'MFA token required', 'mfa_required': True},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Verify MFA token
            if not user.verify_mfa_token(mfa_token):
                # Check backup codes
                if not user.use_backup_code(mfa_token):
                    user.record_failed_login(client_ip)
                    
                    AuditLog.log(
                        action='mfa_failed',
                        user=user,
                        severity='warning',
                        message=f'Failed MFA verification for {user.email}',
                        ip_address=client_ip,
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    return Response(
                        {'error': 'Invalid MFA token'},
                        status=status.HTTP_401_UNAUTHORIZED
                    )
        
        # Check if MFA setup is required
        if user.requires_mfa_setup:
            # Generate temporary token for MFA setup
            setup_token = str(uuid.uuid4())
            request.session['mfa_setup_token'] = setup_token
            request.session['mfa_setup_user_id'] = str(user.id)
            
            return Response({
                'mfa_setup_required': True,
                'setup_token': setup_token
            }, status=status.HTTP_200_OK)
        
        # Successful login
        client_ip, _ = get_client_ip(request)
        user.record_login(client_ip, request.session.session_key)
        
        # Create session monitor
        SessionMonitor.objects.create(
            user=user,
            session_key=request.session.session_key,
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            expires_at=timezone.now() + timedelta(seconds=settings.SESSION_COOKIE_AGE)
        )
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        
        # Log successful login
        AuditLog.log(
            action='login',
            user=user,
            severity='info',
            message=f'Successful login for {user.email}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_key=request.session.session_key
        )
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        })
    
    def _check_failed_login_patterns(self, email, ip_address):
        """Check for suspicious failed login patterns"""
        # Check recent failed attempts from this IP
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_failures = AuditLog.objects.filter(
            action='login_failed',
            ip_address=ip_address,
            timestamp__gte=one_hour_ago
        ).count()
        
        if recent_failures >= 10:
            SecurityAlert.objects.get_or_create(
                alert_type='brute_force',
                ip_address=ip_address,
                status='new',
                defaults={
                    'severity': 'high',
                    'title': f'Possible brute force attack from {ip_address}',
                    'description': f'{recent_failures} failed login attempts in the last hour',
                    'details': {
                        'ip_address': ip_address,
                        'target_email': email,
                        'attempt_count': recent_failures
                    }
                }
            )


class LogoutView(APIView):
    """Logout view with session cleanup"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            # Get session monitor
            session = SessionMonitor.objects.filter(
                user=request.user,
                session_key=request.session.session_key,
                terminated=False
            ).first()
            
            if session:
                session.terminate(request.user, 'User logout')
            
            # Blacklist the refresh token
            token = request.data.get('refresh_token')
            if token:
                try:
                    token = RefreshToken(token)
                    token.blacklist()
                except Exception:
                    pass
            
            # Django logout
            logout(request)
            
            # Log the logout
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='logout',
                user=request.user,
                severity='info',
                message=f'User {request.user.email} logged out',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({'message': 'Successfully logged out'})
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class RegisterView(generics.CreateAPIView):
    """User registration with approval workflow"""
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    
    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Create user
        user = serializer.save()
        
        # Set registration IP
        client_ip, _ = get_client_ip(request)
        user.registration_ip = client_ip
        user.save()
        
        # Log registration
        AuditLog.log(
            action='user_created',
            user=user,
            severity='info',
            message=f'New user registered: {user.email}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            metadata={'approval_required': not user.is_superuser}
        )
        
        # Send notifications
        if not user.is_superuser:
            send_new_user_notification_to_admins.delay(str(user.id))
        
        return Response({
            'message': 'Registration successful. Your account is pending approval.',
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)


class ChangePasswordView(APIView):
    """Change password with validation"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ChangePasswordSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']
        
        # Verify old password
        if not user.check_password(old_password):
            return Response(
                {'error': 'Invalid old password'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update password
        user.set_password(new_password)
        user.update_password_history(make_password(new_password))
        user.save()
        
        # Log password change
        client_ip, _ = get_client_ip(request)
        AuditLog.log(
            action='password_changed',
            user=user,
            severity='info',
            message=f'Password changed for {user.email}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({'message': 'Password changed successfully'})


class PasswordResetRequestView(APIView):
    """Request password reset via email"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response(
                {'error': 'Email is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = CustomUser.objects.get(email=email)
            
            # Generate reset token
            token = str(uuid.uuid4())
            request.session[f'reset_token_{token}'] = {
                'user_id': str(user.id),
                'expires': (timezone.now() + timedelta(hours=1)).isoformat()
            }
            
            # Send email (implement email template)
            # send_password_reset_email.delay(user.id, token)
            
            # Log the request
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='password_reset',
                user=user,
                severity='info',
                message=f'Password reset requested for {user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
        except CustomUser.DoesNotExist:
            pass  # Don't reveal if email exists
        
        return Response({
            'message': 'If the email exists, a password reset link has been sent.'
        })


class PasswordResetConfirmView(APIView):
    """Confirm password reset with token"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        
        if not token or not new_password:
            return Response(
                {'error': 'Token and new password are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify token
        reset_data = request.session.get(f'reset_token_{token}')
        if not reset_data:
            return Response(
                {'error': 'Invalid or expired token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check expiration
        expires = timezone.datetime.fromisoformat(reset_data['expires'])
        if timezone.now() > expires:
            return Response(
                {'error': 'Token has expired'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = CustomUser.objects.get(id=reset_data['user_id'])
            
            # Validate new password
            from django.contrib.auth.password_validation import validate_password
            validate_password(new_password, user)
            
            # Update password
            user.set_password(new_password)
            user.update_password_history(make_password(new_password))
            user.save()
            
            # Clear token
            del request.session[f'reset_token_{token}']
            
            # Log the reset
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='password_reset',
                user=user,
                severity='info',
                message=f'Password reset completed for {user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({'message': 'Password reset successful'})
            
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except ValidationError as e:
            return Response(
                {'error': e.messages},
                status=status.HTTP_400_BAD_REQUEST
            )


class MFASetupView(APIView):
    """Setup MFA for user"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get MFA setup QR code"""
        user = request.user
        
        if user.mfa_enabled:
            return Response(
                {'error': 'MFA is already enabled'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate secret and QR code
        qr_code = user.generate_mfa_qr_code()
        
        return Response({
            'qr_code': qr_code,
            'backup_codes': []  # Don't show until verified
        })
    
    def post(self, request):
        """Verify and enable MFA"""
        serializer = MFAVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        token = serializer.validated_data['token']
        
        # Verify token
        if not user.verify_mfa_token(token):
            return Response(
                {'error': 'Invalid verification code'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Enable MFA
        user.mfa_enabled = True
        user.mfa_enforced_at = timezone.now()
        
        # Generate backup codes
        backup_codes = user.generate_backup_codes()
        user.save()
        
        # Log MFA enablement
        client_ip, _ = get_client_ip(request)
        AuditLog.log(
            action='mfa_enabled',
            user=user,
            severity='info',
            message=f'MFA enabled for {user.email}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        return Response({
            'message': 'MFA enabled successfully',
            'backup_codes': backup_codes
        })


class MFAVerifyView(APIView):
    """Verify MFA token during login"""
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        # This is handled in the login view
        # Kept for potential separate MFA verification flow
        return Response({'error': 'Use login endpoint'}, status=status.HTTP_400_BAD_REQUEST)


class MFADisableView(APIView):
    """Disable MFA (requires current password)"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        password = request.data.get('password')
        
        if not password:
            return Response(
                {'error': 'Password is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = request.user
        
        # Verify password
        if not user.check_password(password):
            return Response(
                {'error': 'Invalid password'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret = ''
        user.mfa_backup_codes = []
        user.save()
        
        # Log MFA disable
        client_ip, _ = get_client_ip(request)
        AuditLog.log(
            action='mfa_disabled',
            user=user,
            severity='warning',
            message=f'MFA disabled for {user.email}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Create security alert
        SecurityAlert.objects.create(
            alert_type='mfa_bypass',
            severity='high',
            title=f'MFA disabled for user {user.email}',
            description='User has disabled two-factor authentication',
            user=user,
            ip_address=client_ip,
            details={'reason': 'User initiated'}
        )
        
        return Response({'message': 'MFA disabled successfully'})


class MFABackupCodesView(APIView):
    """Regenerate MFA backup codes"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        user = request.user
        
        if not user.mfa_enabled:
            return Response(
                {'error': 'MFA is not enabled'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify current password or MFA token
        password = request.data.get('password')
        mfa_token = request.data.get('mfa_token')
        
        if password and user.check_password(password):
            # Generate new backup codes
            backup_codes = user.generate_backup_codes()
            
            # Log the regeneration
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='data_modified',
                user=user,
                severity='info',
                message=f'MFA backup codes regenerated for {user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({
                'backup_codes': backup_codes
            })
        elif mfa_token and user.verify_mfa_token(mfa_token):
            # Generate new backup codes
            backup_codes = user.generate_backup_codes()
            
            return Response({
                'backup_codes': backup_codes
            })
        else:
            return Response(
                {'error': 'Invalid password or MFA token'},
                status=status.HTTP_401_UNAUTHORIZED
            )


class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile view and update"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        
        # Log profile update
        client_ip, _ = get_client_ip(request)
        AuditLog.log(
            action='user_updated',
            user=request.user,
            severity='info',
            message=f'Profile updated for {request.user.email}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            metadata={'fields_updated': list(request.data.keys())}
        )
        
        return response


class UpdateProfileView(UserProfileView):
    """Alias for profile update"""
    pass


# Admin views
class UserListView(generics.ListAPIView):
    """List all users (admin only)"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = UserListSerializer
    
    def get_queryset(self):
        queryset = CustomUser.objects.all()
        
        # Filters
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(approval_status=status_filter)
        
        user_type = self.request.query_params.get('user_type')
        if user_type:
            queryset = queryset.filter(user_type=user_type)
        
        mfa_enabled = self.request.query_params.get('mfa_enabled')
        if mfa_enabled is not None:
            queryset = queryset.filter(mfa_enabled=mfa_enabled.lower() == 'true')
        
        return queryset.order_by('-date_joined')


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """User detail view (admin only)"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer
    queryset = CustomUser.objects.all()
    
    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        
        # Log user deletion
        client_ip, _ = get_client_ip(request)
        AuditLog.log(
            action='user_deleted',
            user=request.user,
            severity='warning',
            message=f'User {user.email} deleted by {request.user.email}',
            ip_address=client_ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            content_object=user
        )
        
        return super().destroy(request, *args, **kwargs)


class ApproveUserView(APIView):
    """Approve user registration"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
            
            if user.is_approved:
                return Response(
                    {'error': 'User is already approved'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Approve user
            user.approve_user(request.user)
            
            # Send notification
            send_approval_notification.delay(str(user.id), str(request.user.id), 'approved')
            
            # Log approval
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='user_approved',
                user=request.user,
                severity='info',
                message=f'User {user.email} approved by {request.user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                content_object=user
            )
            
            return Response({
                'message': 'User approved successfully',
                'user': UserSerializer(user).data
            })
            
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class RejectUserView(APIView):
    """Reject user registration"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
            
            # Reject user
            user.reject_user(request.user)
            
            # Send notification
            send_approval_notification.delay(str(user.id), str(request.user.id), 'rejected')
            
            # Log rejection
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='user_rejected',
                user=request.user,
                severity='info',
                message=f'User {user.email} rejected by {request.user.email}',
                ip_address=client_ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                content_object=user
            )
            
            return Response({
                'message': 'User rejected',
                'user': UserSerializer(user).data
            })
            
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
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