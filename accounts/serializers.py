# accounts/serializers.py

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import CustomUser
from security_suite.models import SessionMonitor


class UserSerializer(serializers.ModelSerializer):
    """Full user serializer"""
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    is_admin = serializers.BooleanField(read_only=True)
    requires_mfa_setup = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'line_user_id', 'line_display_name', 'is_active', 'is_staff',
            'is_approved', 'approval_status', 'user_type', 'is_admin',
            'mfa_enabled', 'requires_mfa_setup', 'date_joined',
            'last_login', 'last_activity', 'approved_at'
        ]
        read_only_fields = [
            'id', 'date_joined', 'last_login', 'last_activity',
            'approved_at', 'is_approved', 'approval_status'
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    """User profile serializer for self-update"""
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'line_display_name', 'mfa_enabled', 'date_joined',
            'last_login', 'last_password_change'
        ]
        read_only_fields = [
            'id', 'email', 'date_joined', 'last_login',
            'last_password_change', 'mfa_enabled'
        ]


class UserListSerializer(serializers.ModelSerializer):
    """Simplified user serializer for lists"""
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    active_sessions = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'full_name', 'user_type', 'is_active',
            'is_approved', 'approval_status', 'mfa_enabled',
            'last_activity', 'active_sessions'
        ]
    
    def get_active_sessions(self, obj):
        return SessionMonitor.objects.filter(
            user=obj,
            terminated=False
        ).count()


class LoginSerializer(serializers.Serializer):
    """Login serializer with MFA support"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    mfa_token = serializers.CharField(required=False, allow_blank=True)
    
    def validate_email(self, value):
        return value.lower()


class RegisterSerializer(serializers.ModelSerializer):
    """Registration serializer"""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustomUser
        fields = [
            'email', 'password', 'password_confirm', 'first_name',
            'last_name', 'line_user_id', 'line_display_name'
        ]
    
    def validate_email(self, value):
        return value.lower()
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        attrs.pop('password_confirm')
        return attrs
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        
        # Create user
        user = CustomUser.objects.create_user(
            password=password,
            **validated_data
        )
        
        return user


class ChangePasswordSerializer(serializers.Serializer):
    """Change password serializer"""
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        
        # Validate new password
        user = self.context['request'].user
        try:
            validate_password(attrs['new_password'], user)
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': e.messages})
        
        return attrs


class MFASetupSerializer(serializers.Serializer):
    """MFA setup serializer"""
    token = serializers.CharField()


class MFAVerifySerializer(serializers.Serializer):
    """MFA verification serializer"""
    token = serializers.CharField()


class ApprovalQueueSerializer(serializers.ModelSerializer):
    """User serializer for approval queue"""
    days_pending = serializers.SerializerMethodField()
    
    class Meta:
        model = CustomUser
        fields = [
            'id', 'email', 'first_name', 'last_name', 'line_display_name',
            'date_joined', 'registration_ip', 'days_pending'
        ]
    
    def get_days_pending(self, obj):
        from django.utils import timezone
        return (timezone.now() - obj.date_joined).days


class SessionSerializer(serializers.ModelSerializer):
    """Session monitor serializer"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    duration = serializers.SerializerMethodField()
    is_current = serializers.SerializerMethodField()
    
    class Meta:
        model = SessionMonitor
        fields = [
            'id', 'user_email', 'ip_address', 'user_agent', 'country',
            'city', 'created_at', 'last_activity', 'expires_at',
            'duration', 'is_suspicious', 'is_current'
        ]
    
    def get_duration(self, obj):
        from django.utils import timezone
        duration = timezone.now() - obj.created_at
        hours = int(duration.total_seconds() // 3600)
        minutes = int((duration.total_seconds() % 3600) // 60)
        return f"{hours}h {minutes}m"
    
    def get_is_current(self, obj):
        request = self.context.get('request')
        if request and hasattr(request, 'session'):
            return obj.session_key == request.session.session_key
        return False