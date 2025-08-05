# security_suite/permissions.py

from rest_framework import permissions
from django.utils.translation import gettext_lazy as _


class IsAlertOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners of an alert or staff to view/edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Staff can access all alerts
        if request.user.is_staff:
            return True
        
        # Check if user is the alert owner or creator
        return (
            obj.user == request.user or 
            obj.created_by == request.user or
            obj.acknowledged_by == request.user or
            obj.resolved_by == request.user
        )


class IsSessionOwner(permissions.BasePermission):
    """
    Custom permission to only allow session owners or admins to view/terminate sessions.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admins can access all sessions
        if request.user.is_staff:
            return True
        
        # Users can only access their own sessions
        return obj.user == request.user


class CanManageBlacklist(permissions.BasePermission):
    """
    Permission to manage IP blacklist entries.
    """
    message = _('You do not have permission to manage IP blacklist.')
    
    def has_permission(self, request, view):
        # Must be authenticated
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Must be staff or have specific permission
        return (
            request.user.is_staff or 
            request.user.has_perm('security_suite.add_ipblacklist') or
            request.user.has_perm('security_suite.change_ipblacklist')
        )


class CanViewSecurityData(permissions.BasePermission):
    """
    Permission to view security dashboards and reports.
    """
    message = _('You do not have permission to view security data.')
    
    def has_permission(self, request, view):
        # Must be authenticated
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Staff can always view
        if request.user.is_staff:
            return True
        
        # Check for specific permissions
        return (
            request.user.has_perm('security_suite.view_securityalert') or
            request.user.has_perm('security_suite.view_dashboard') or
            hasattr(request.user, 'security_viewer') and request.user.security_viewer
        )


class CanModifySecurityConfig(permissions.BasePermission):
    """
    Permission to modify security configuration.
    Only superusers should have this permission.
    """
    message = _('Only superusers can modify security configuration.')
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class CanManageThreatIntel(permissions.BasePermission):
    """
    Permission to manage threat intelligence entries.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Read-only access for staff
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_staff
        
        # Write access for specific permission or superuser
        return (
            request.user.is_superuser or
            request.user.has_perm('security_suite.add_threatintelligence')
        )


class CanGenerateReports(permissions.BasePermission):
    """
    Permission to generate security reports.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        return (
            request.user.is_staff or
            request.user.has_perm('security_suite.add_securityreport')
        )


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Generic permission for owner or admin access.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admins have full access
        if request.user.is_staff:
            return True
        
        # Check various owner fields
        owner_fields = ['user', 'created_by', 'requested_by', 'blocked_by']
        
        for field in owner_fields:
            if hasattr(obj, field):
                owner = getattr(obj, field)
                if owner == request.user:
                    return True
        
        return False


class RateLimitPermission(permissions.BasePermission):
    """
    Permission class to check rate limiting.
    """
    message = _('Rate limit exceeded. Please try again later.')
    
    def has_permission(self, request, view):
        # This is handled by the @ratelimit decorator
        # But we can add additional checks here if needed
        if hasattr(request, 'limited') and request.limited:
            return False
        return True