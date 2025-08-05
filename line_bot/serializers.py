from rest_framework import serializers
from django.utils import timezone
from .models import LineGroup, GroupMembership, BotCommand, CommandExecution, LineMessage
from accounts.serializers import UserSerializer


class LineGroupSerializer(serializers.ModelSerializer):
    """Serializer for LINE groups"""
    admin_count = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()
    password_expired = serializers.SerializerMethodField()
    
    class Meta:
        model = LineGroup
        fields = [
            'id', 'group_id', 'group_name', 'is_active',
            'auto_remove_unauthorized', 'password_expiry_days',
            'max_members', 'total_members', 'created_at', 'updated_at',
            'password_changed_at', 'admin_count', 'member_count',
            'password_expired', 'unauthorized_attempts'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'password_changed_at',
            'total_members', 'unauthorized_attempts'
        ]
        extra_kwargs = {
            'encrypted_password': {'write_only': True}
        }
    
    def get_admin_count(self, obj):
        return obj.admins.count()
    
    def get_member_count(self, obj):
        return GroupMembership.objects.filter(
            group=obj,
            validation_status='validated'
        ).count()
    
    def get_password_expired(self, obj):
        return obj.is_password_expired()
    
    def create(self, validated_data):
        # Password will be set separately via the change password endpoint
        validated_data.pop('encrypted_password', None)
        return super().create(validated_data)


class GroupDetailSerializer(LineGroupSerializer):
    """Detailed serializer for LINE groups"""
    admins = UserSerializer(many=True, read_only=True)
    recent_activity = serializers.SerializerMethodField()
    
    class Meta(LineGroupSerializer.Meta):
        fields = LineGroupSerializer.Meta.fields + [
            'admins', 'recent_activity'
        ]
    
    def get_recent_activity(self, obj):
        """Get recent activity summary"""
        last_7_days = timezone.now() - timezone.timedelta(days=7)
        
        return {
            'messages_7d': LineMessage.objects.filter(
                group=obj,
                received_at__gte=last_7_days
            ).count(),
            'commands_7d': CommandExecution.objects.filter(
                group=obj,
                executed_at__gte=last_7_days
            ).count(),
            'new_members_7d': GroupMembership.objects.filter(
                group=obj,
                joined_at__gte=last_7_days
            ).count(),
        }


class GroupMembershipSerializer(serializers.ModelSerializer):
    """Serializer for group memberships"""
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.CharField(source='user.line_display_name', read_only=True)
    group_name = serializers.CharField(source='group.group_name', read_only=True)
    validation_status_display = serializers.CharField(
        source='get_validation_status_display',
        read_only=True
    )
    membership_duration = serializers.SerializerMethodField()
    
    class Meta:
        model = GroupMembership
        fields = [
            'id', 'user', 'user_email', 'user_name', 'group', 'group_name',
            'line_member_id', 'joined_at', 'validated_at', 'removed_at',
            'validation_status', 'validation_status_display',
            'validation_attempts', 'membership_duration'
        ]
        read_only_fields = [
            'line_member_id', 'joined_at', 'validated_at', 'removed_at',
            'validation_attempts'
        ]
    
    def get_membership_duration(self, obj):
        """Get membership duration"""
        if obj.removed_at:
            duration = obj.removed_at - obj.joined_at
        else:
            duration = timezone.now() - obj.joined_at
        
        days = duration.days
        if days > 0:
            return f"{days} days"
        else:
            hours = duration.seconds // 3600
            return f"{hours} hours"


class BotCommandSerializer(serializers.ModelSerializer):
    """Serializer for bot commands"""
    permission_level_display = serializers.CharField(
        source='get_permission_level_display',
        read_only=True
    )
    last_used_by_email = serializers.CharField(
        source='last_used_by.email',
        read_only=True,
        allow_null=True
    )
    can_execute_by_user = serializers.SerializerMethodField()
    
    class Meta:
        model = BotCommand
        fields = [
            'id', 'command', 'description', 'permission_level',
            'permission_level_display', 'is_active', 'usage_count',
            'last_used_at', 'last_used_by', 'last_used_by_email',
            'created_at', 'updated_at', 'can_execute_by_user'
        ]
        read_only_fields = [
            'usage_count', 'last_used_at', 'last_used_by',
            'created_at', 'updated_at'
        ]
    
    def get_can_execute_by_user(self, obj):
        """Check if current user can execute this command"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            return obj.can_execute(request.user)
        return False
    
    def validate_command(self, value):
        """Validate command format"""
        if not value.isalnum():
            raise serializers.ValidationError(
                "Command must contain only letters and numbers"
            )
        return value.lower()


class CommandExecutionSerializer(serializers.ModelSerializer):
    """Serializer for command executions"""
    command_name = serializers.CharField(source='command.command', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.CharField(source='user.line_display_name', read_only=True)
    group_name = serializers.CharField(
        source='group.group_name',
        read_only=True,
        allow_null=True
    )
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = CommandExecution
        fields = [
            'id', 'command', 'command_name', 'user', 'user_email', 'user_name',
            'group', 'group_name', 'raw_command', 'parameters', 'status',
            'status_display', 'error_message', 'response_sent', 'executed_at',
            'execution_time_ms', 'ip_address'
        ]
        read_only_fields = fields  # All fields are read-only


class LineMessageSerializer(serializers.ModelSerializer):
    """Serializer for LINE messages"""
    message_type_display = serializers.CharField(
        source='get_message_type_display',
        read_only=True
    )
    user_email = serializers.CharField(
        source='user.email',
        read_only=True,
        allow_null=True
    )
    user_name = serializers.CharField(
        source='user.line_display_name',
        read_only=True,
        allow_null=True
    )
    group_name = serializers.CharField(
        source='group.group_name',
        read_only=True,
        allow_null=True
    )
    processing_time = serializers.SerializerMethodField()
    
    class Meta:
        model = LineMessage
        fields = [
            'id', 'message_id', 'user', 'user_email', 'user_name',
            'group', 'group_name', 'message_type', 'message_type_display',
            'content', 'received_at', 'processed_at', 'is_command',
            'command_execution', 'processing_time'
        ]
        read_only_fields = fields  # All fields are read-only
    
    def get_processing_time(self, obj):
        """Get message processing time"""
        if obj.processed_at and obj.received_at:
            diff = obj.processed_at - obj.received_at
            return f"{diff.total_seconds():.2f}s"
        return None


class CommandStatisticsSerializer(serializers.Serializer):
    """Serializer for command statistics"""
    command = serializers.CharField()
    description = serializers.CharField()
    permission_level = serializers.CharField()
    is_active = serializers.BooleanField()
    total_executions = serializers.IntegerField()
    success_count = serializers.IntegerField()
    failed_count = serializers.IntegerField()
    success_rate = serializers.FloatField()
    avg_execution_time = serializers.FloatField()
    last_used = serializers.DateTimeField(allow_null=True)


class BotStatisticsSerializer(serializers.Serializer):
    """Serializer for bot statistics"""
    period = serializers.CharField()
    statistics = serializers.DictField()
    top_commands = serializers.ListField()
    active_groups = serializers.ListField()
    timeline = serializers.ListField()