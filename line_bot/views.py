# line_bot/views.py

from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.db.models import Count, Q, F, Avg
from django.utils import timezone
from datetime import timedelta
from ipware import get_client_ip

from .models import LineGroup, GroupMembership, BotCommand, CommandExecution, LineMessage
from .serializers import (
    LineGroupSerializer, GroupMembershipSerializer, BotCommandSerializer,
    CommandExecutionSerializer, LineMessageSerializer, GroupDetailSerializer,
    CommandStatisticsSerializer, BotStatisticsSerializer
)
from accounts.permissions import IsAdminUser, IsSuperUser
from audit_trail.models import AuditLog
from security_suite.models import SecurityAlert


class GroupListView(generics.ListCreateAPIView):
    """List and create LINE groups"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = LineGroupSerializer
    
    def get_queryset(self):
        queryset = LineGroup.objects.all()
        
        # Filter by active status
        is_active = self.request.query_params.get('active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Filter by admin
        admin_id = self.request.query_params.get('admin_id')
        if admin_id:
            queryset = queryset.filter(admins__id=admin_id)
        
        # Search by name
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(group_name__icontains=search) |
                Q(group_id__icontains=search)
            )
        
        return queryset.order_by('-created_at')
    
    def perform_create(self, serializer):
        group = serializer.save()
        
        # Add creator as admin
        group.admins.add(self.request.user)
        
        # Log creation
        client_ip, _ = get_client_ip(self.request)
        AuditLog.log(
            action='group_created',
            user=self.request.user,
            severity='info',
            message=f'LINE group created: {group.group_name}',
            ip_address=client_ip,
            content_object=group
        )


class GroupCreateView(GroupListView):
    """Alias for group creation"""
    pass


class GroupDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Get, update, or delete a LINE group"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    queryset = LineGroup.objects.all()
    
    def get_serializer_class(self):
        if self.request.method == 'GET':
            return GroupDetailSerializer
        return LineGroupSerializer
    
    def perform_update(self, serializer):
        group = serializer.save()
        
        # Log update
        client_ip, _ = get_client_ip(self.request)
        AuditLog.log(
            action='group_updated',
            user=self.request.user,
            severity='info',
            message=f'LINE group updated: {group.group_name}',
            ip_address=client_ip,
            content_object=group,
            metadata={'changes': self.request.data}
        )
    
    def perform_destroy(self, instance):
        group_name = instance.group_name
        
        # Log deletion
        client_ip, _ = get_client_ip(self.request)
        AuditLog.log(
            action='group_deleted',
            user=self.request.user,
            severity='warning',
            message=f'LINE group deleted: {group_name}',
            ip_address=client_ip,
            metadata={'group_id': str(instance.id)}
        )
        
        instance.delete()


class GroupUpdateView(GroupDetailView):
    """Alias for group update"""
    pass


class GroupDeleteView(GroupDetailView):
    """Alias for group deletion"""
    pass


class GroupChangePasswordView(APIView):
    """Change group password"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request, pk):
        try:
            group = LineGroup.objects.get(pk=pk)
            
            # Check if user is group admin
            if not (group.admins.filter(id=request.user.id).exists() or request.user.is_superuser):
                return Response(
                    {'error': 'Only group admins can change the password'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            new_password = request.data.get('password')
            if not new_password:
                return Response(
                    {'error': 'Password is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate password strength
            if len(new_password) < 8:
                return Response(
                    {'error': 'Password must be at least 8 characters long'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Set new password
            group.set_password(new_password)
            
            # Log password change
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='group_password_changed',
                user=request.user,
                severity='info',
                message=f'Password changed for group: {group.group_name}',
                ip_address=client_ip,
                content_object=group
            )
            
            # Create security alert
            SecurityAlert.objects.create(
                alert_type='suspicious_activity',
                severity='low',
                title=f'Group password changed: {group.group_name}',
                description=f'Password changed by {request.user.email}',
                user=request.user,
                details={'group_id': str(group.id)}
            )
            
            return Response({'message': 'Password changed successfully'})
            
        except LineGroup.DoesNotExist:
            return Response(
                {'error': 'Group not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class GroupMembersView(generics.ListAPIView):
    """List group members"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = GroupMembershipSerializer
    
    def get_queryset(self):
        group_id = self.kwargs.get('pk')
        queryset = GroupMembership.objects.filter(group_id=group_id)
        
        # Filter by validation status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(validation_status=status_filter)
        
        return queryset.order_by('-joined_at')


class RemoveGroupMemberView(APIView):
    """Remove member from group"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request, pk, member_id):
        try:
            group = LineGroup.objects.get(pk=pk)
            membership = GroupMembership.objects.get(
                id=member_id,
                group=group
            )
            
            # Check permissions
            if not (group.admins.filter(id=request.user.id).exists() or request.user.is_superuser):
                return Response(
                    {'error': 'Only group admins can remove members'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Don't allow removing admins
            if membership.user.is_admin:
                return Response(
                    {'error': 'Cannot remove admin users'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Mark as removed
            membership.mark_as_removed()
            
            # Update group member count
            group.total_members = GroupMembership.objects.filter(
                group=group,
                validation_status='validated'
            ).count()
            group.save()
            
            # Log removal
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='group_member_removed',
                user=request.user,
                severity='warning',
                message=f'{membership.user.email} removed from {group.group_name}',
                ip_address=client_ip,
                content_object=group,
                metadata={'removed_user_id': str(membership.user.id)}
            )
            
            return Response({'message': 'Member removed successfully'})
            
        except (LineGroup.DoesNotExist, GroupMembership.DoesNotExist):
            return Response(
                {'error': 'Group or member not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class CommandListView(generics.ListCreateAPIView):
    """List and create bot commands"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = BotCommandSerializer
    
    def get_queryset(self):
        queryset = BotCommand.objects.all()
        
        # Filter by permission level
        permission = self.request.query_params.get('permission')
        if permission:
            queryset = queryset.filter(permission_level=permission)
        
        # Filter by active status
        is_active = self.request.query_params.get('active')
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        return queryset.order_by('command')
    
    def perform_create(self, serializer):
        command = serializer.save()
        
        # Log creation
        client_ip, _ = get_client_ip(self.request)
        AuditLog.log(
            action='config_changed',
            user=self.request.user,
            severity='info',
            message=f'Bot command created: /{command.command}',
            ip_address=client_ip,
            content_object=command
        )


class CommandCreateView(CommandListView):
    """Alias for command creation"""
    pass


class CommandDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Get, update, or delete a bot command"""
    permission_classes = [permissions.IsAuthenticated, IsSuperUser]
    serializer_class = BotCommandSerializer
    queryset = BotCommand.objects.all()
    
    def perform_update(self, serializer):
        command = serializer.save()
        
        # Log update
        client_ip, _ = get_client_ip(self.request)
        AuditLog.log(
            action='config_changed',
            user=self.request.user,
            severity='info',
            message=f'Bot command updated: /{command.command}',
            ip_address=client_ip,
            content_object=command,
            metadata={'changes': self.request.data}
        )


class CommandUpdateView(CommandDetailView):
    """Alias for command update"""
    pass


class CommandToggleView(APIView):
    """Toggle command active status"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def post(self, request, pk):
        try:
            command = BotCommand.objects.get(pk=pk)
            command.is_active = not command.is_active
            command.save()
            
            # Log toggle
            client_ip, _ = get_client_ip(request)
            AuditLog.log(
                action='config_changed',
                user=request.user,
                severity='info',
                message=f'Bot command {"enabled" if command.is_active else "disabled"}: /{command.command}',
                ip_address=client_ip,
                content_object=command
            )
            
            return Response({
                'message': f'Command {"enabled" if command.is_active else "disabled"}',
                'is_active': command.is_active
            })
            
        except BotCommand.DoesNotExist:
            return Response(
                {'error': 'Command not found'},
                status=status.HTTP_404_NOT_FOUND
            )


class CommandExecutionListView(generics.ListAPIView):
    """List command executions"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = CommandExecutionSerializer
    
    def get_queryset(self):
        queryset = CommandExecution.objects.all()
        
        # Filter by command
        command_id = self.request.query_params.get('command_id')
        if command_id:
            queryset = queryset.filter(command_id=command_id)
        
        # Filter by user
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by group
        group_id = self.request.query_params.get('group_id')
        if group_id:
            queryset = queryset.filter(group_id=group_id)
        
        # Filter by status
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date and end_date:
            queryset = queryset.filter(
                executed_at__date__range=[start_date, end_date]
            )
        
        return queryset.order_by('-executed_at')


class CommandExecutionDetailView(generics.RetrieveAPIView):
    """Get command execution details"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = CommandExecutionSerializer
    queryset = CommandExecution.objects.all()


class MessageListView(generics.ListAPIView):
    """List LINE messages"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = LineMessageSerializer
    
    def get_queryset(self):
        queryset = LineMessage.objects.all()
        
        # Filter by message type
        msg_type = self.request.query_params.get('type')
        if msg_type:
            queryset = queryset.filter(message_type=msg_type)
        
        # Filter by user
        user_id = self.request.query_params.get('user_id')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by group
        group_id = self.request.query_params.get('group_id')
        if group_id:
            queryset = queryset.filter(group_id=group_id)
        
        # Filter by command messages
        commands_only = self.request.query_params.get('commands_only')
        if commands_only and commands_only.lower() == 'true':
            queryset = queryset.filter(is_command=True)
        
        # Date range
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        if start_date and end_date:
            queryset = queryset.filter(
                received_at__date__range=[start_date, end_date]
            )
        
        return queryset.order_by('-received_at')


class MessageDetailView(generics.RetrieveAPIView):
    """Get message details"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    serializer_class = LineMessageSerializer
    queryset = LineMessage.objects.all()


class BotStatisticsView(APIView):
    """Get comprehensive bot statistics"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        period = request.query_params.get('period', '7d')
        
        # Determine time range
        now = timezone.now()
        if period == '24h':
            start_date = now - timedelta(hours=24)
        elif period == '30d':
            start_date = now - timedelta(days=30)
        else:  # Default 7d
            start_date = now - timedelta(days=7)
        
        # General statistics
        from accounts.models import CustomUser
        stats = {
            'users': {
                'total': CustomUser.objects.filter(line_user_id__isnull=False).count(),
                'approved': CustomUser.objects.filter(
                    line_user_id__isnull=False,
                    is_approved=True
                ).count(),
                'pending': CustomUser.objects.filter(
                    line_user_id__isnull=False,
                    approval_status='pending'
                ).count(),
                'new_period': CustomUser.objects.filter(
                    line_user_id__isnull=False,
                    date_joined__gte=start_date
                ).count(),
            },
            'groups': {
                'total': LineGroup.objects.count(),
                'active': LineGroup.objects.filter(is_active=True).count(),
                'created_period': LineGroup.objects.filter(
                    created_at__gte=start_date
                ).count(),
            },
            'messages': {
                'total': LineMessage.objects.count(),
                'period': LineMessage.objects.filter(
                    received_at__gte=start_date
                ).count(),
                'commands': LineMessage.objects.filter(
                    received_at__gte=start_date,
                    is_command=True
                ).count(),
            },
            'commands': {
                'total_executions': CommandExecution.objects.count(),
                'period_executions': CommandExecution.objects.filter(
                    executed_at__gte=start_date
                ).count(),
                'success_rate': self._calculate_success_rate(start_date),
                'avg_execution_time': self._calculate_avg_execution_time(start_date),
            },
            'memberships': {
                'total': GroupMembership.objects.filter(
                    validation_status='validated'
                ).count(),
                'new_period': GroupMembership.objects.filter(
                    joined_at__gte=start_date
                ).count(),
                'failed_period': GroupMembership.objects.filter(
                    joined_at__gte=start_date,
                    validation_status='failed'
                ).count(),
            }
        }
        
        # Top commands
        top_commands = CommandExecution.objects.filter(
            executed_at__gte=start_date
        ).values('command__command').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Most active groups
        active_groups = CommandExecution.objects.filter(
            executed_at__gte=start_date,
            group__isnull=False
        ).values('group__group_name').annotate(
            activity=Count('id')
        ).order_by('-activity')[:10]
        
        # Activity timeline
        timeline = []
        for i in range(7):
            date = (now - timedelta(days=i)).date()
            timeline.append({
                'date': date.isoformat(),
                'messages': LineMessage.objects.filter(
                    received_at__date=date
                ).count(),
                'commands': CommandExecution.objects.filter(
                    executed_at__date=date
                ).count(),
                'new_users': CustomUser.objects.filter(
                    line_user_id__isnull=False,
                    date_joined__date=date
                ).count(),
            })
        
        return Response({
            'period': period,
            'statistics': stats,
            'top_commands': list(top_commands),
            'active_groups': list(active_groups),
            'timeline': timeline,
        })
    
    def _calculate_success_rate(self, start_date):
        """Calculate command success rate"""
        total = CommandExecution.objects.filter(
            executed_at__gte=start_date
        ).count()
        
        if total == 0:
            return 100.0
        
        success = CommandExecution.objects.filter(
            executed_at__gte=start_date,
            status='success'
        ).count()
        
        return round((success / total) * 100, 2)
    
    def _calculate_avg_execution_time(self, start_date):
        """Calculate average command execution time"""
        avg_time = CommandExecution.objects.filter(
            executed_at__gte=start_date,
            status='success'
        ).aggregate(avg_time=Avg('execution_time_ms'))['avg_time']
        
        return round(avg_time or 0, 2)


class GroupStatisticsView(APIView):
    """Get statistics for a specific group"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        group_id = request.query_params.get('group_id')
        if not group_id:
            return Response(
                {'error': 'group_id parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            group = LineGroup.objects.get(id=group_id)
        except LineGroup.DoesNotExist:
            return Response(
                {'error': 'Group not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Time range
        period = request.query_params.get('period', '7d')
        now = timezone.now()
        if period == '24h':
            start_date = now - timedelta(hours=24)
        elif period == '30d':
            start_date = now - timedelta(days=30)
        else:  # Default 7d
            start_date = now - timedelta(days=7)
        
        # Group statistics
        stats = {
            'group': {
                'name': group.group_name,
                'id': str(group.id),
                'created': group.created_at.isoformat(),
                'is_active': group.is_active,
                'total_members': group.total_members,
                'password_age_days': (now - group.password_changed_at).days,
            },
            'members': {
                'validated': GroupMembership.objects.filter(
                    group=group,
                    validation_status='validated'
                ).count(),
                'pending': GroupMembership.objects.filter(
                    group=group,
                    validation_status='pending'
                ).count(),
                'failed': GroupMembership.objects.filter(
                    group=group,
                    validation_status='failed'
                ).count(),
                'new_period': GroupMembership.objects.filter(
                    group=group,
                    joined_at__gte=start_date
                ).count(),
            },
            'activity': {
                'messages': LineMessage.objects.filter(
                    group=group,
                    received_at__gte=start_date
                ).count(),
                'commands': CommandExecution.objects.filter(
                    group=group,
                    executed_at__gte=start_date
                ).count(),
                'failed_validations': group.unauthorized_attempts,
            },
            'top_users': self._get_top_users(group, start_date),
            'command_usage': self._get_command_usage(group, start_date),
        }
        
        return Response(stats)
    
    def _get_top_users(self, group, start_date):
        """Get most active users in group"""
        return list(CommandExecution.objects.filter(
            group=group,
            executed_at__gte=start_date
        ).values('user__email', 'user__line_display_name').annotate(
            command_count=Count('id')
        ).order_by('-command_count')[:5])
    
    def _get_command_usage(self, group, start_date):
        """Get command usage statistics for group"""
        return list(CommandExecution.objects.filter(
            group=group,
            executed_at__gte=start_date
        ).values('command__command').annotate(
            usage_count=Count('id')
        ).order_by('-usage_count'))


class CommandStatisticsView(APIView):
    """Get statistics for commands"""
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        # Get all commands with usage stats
        commands = BotCommand.objects.all().annotate(
            total_executions=Count('executions'),
            success_count=Count('executions', filter=Q(executions__status='success')),
            failed_count=Count('executions', filter=Q(executions__status='failed')),
            avg_execution_time=Avg('executions__execution_time_ms')
        )
        
        # Filter by permission level if specified
        permission = request.query_params.get('permission')
        if permission:
            commands = commands.filter(permission_level=permission)
        
        # Calculate success rates
        command_stats = []
        for cmd in commands:
            total = cmd.total_executions
            success_rate = 0
            if total > 0:
                success_rate = round((cmd.success_count / total) * 100, 2)
            
            command_stats.append({
                'command': cmd.command,
                'description': cmd.description,
                'permission_level': cmd.permission_level,
                'is_active': cmd.is_active,
                'total_executions': total,
                'success_count': cmd.success_count,
                'failed_count': cmd.failed_count,
                'success_rate': success_rate,
                'avg_execution_time': round(cmd.avg_execution_time or 0, 2),
                'last_used': cmd.last_used_at.isoformat() if cmd.last_used_at else None,
            })
        
        # Sort by usage
        command_stats.sort(key=lambda x: x['total_executions'], reverse=True)
        
        return Response({
            'total_commands': len(command_stats),
            'active_commands': sum(1 for c in command_stats if c['is_active']),
            'commands': command_stats,
        })