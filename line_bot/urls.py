from django.urls import path
from . import views

app_name = 'line_bot'

urlpatterns = [
    # Group Management
    path('groups/', views.GroupListView.as_view(), name='group_list'),
    path('groups/create/', views.GroupCreateView.as_view(), name='group_create'),
    path('groups/<uuid:pk>/', views.GroupDetailView.as_view(), name='group_detail'),
    path('groups/<uuid:pk>/update/', views.GroupUpdateView.as_view(), name='group_update'),
    path('groups/<uuid:pk>/delete/', views.GroupDeleteView.as_view(), name='group_delete'),
    path('groups/<uuid:pk>/change-password/', views.GroupChangePasswordView.as_view(), name='group_change_password'),
    
    # Group Members
    path('groups/<uuid:pk>/members/', views.GroupMembersView.as_view(), name='group_members'),
    path('groups/<uuid:pk>/members/<uuid:member_id>/remove/', views.RemoveGroupMemberView.as_view(), name='remove_member'),
    
    # Commands
    path('commands/', views.CommandListView.as_view(), name='command_list'),
    path('commands/create/', views.CommandCreateView.as_view(), name='command_create'),
    path('commands/<uuid:pk>/', views.CommandDetailView.as_view(), name='command_detail'),
    path('commands/<uuid:pk>/update/', views.CommandUpdateView.as_view(), name='command_update'),
    path('commands/<uuid:pk>/toggle/', views.CommandToggleView.as_view(), name='command_toggle'),
    
    # Command Execution History
    path('executions/', views.CommandExecutionListView.as_view(), name='execution_list'),
    path('executions/<uuid:pk>/', views.CommandExecutionDetailView.as_view(), name='execution_detail'),
    
    # Messages
    path('messages/', views.MessageListView.as_view(), name='message_list'),
    path('messages/<uuid:pk>/', views.MessageDetailView.as_view(), name='message_detail'),
    
    # Statistics
    path('stats/', views.BotStatisticsView.as_view(), name='bot_stats'),
    path('stats/groups/', views.GroupStatisticsView.as_view(), name='group_stats'),
    path('stats/commands/', views.CommandStatisticsView.as_view(), name='command_stats'),
]
