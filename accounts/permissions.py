# accounts/permissions.py

from rest_framework import permissions


class IsAdminUser(permissions.BasePermission):
    """
    Custom permission to only allow admin users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_admin


class IsSuperUser(permissions.BasePermission):
    """
    Custom permission to only allow superusers.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object or admins to view/edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admin users have all permissions
        if request.user.is_admin:
            return True
        
        # Check if user is the owner
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user
        
        # For User model
        return obj == request.user


class IsApprovedUser(permissions.BasePermission):
    """
    Custom permission to only allow approved users.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            (request.user.is_approved or request.user.is_superuser)
        )


class HasMFAEnabled(permissions.BasePermission):
    """
    Custom permission to require MFA enabled.
    """
    
    message = 'Two-factor authentication is required for this action.'
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.mfa_enabled
        )