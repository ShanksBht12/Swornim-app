# myapp/admin.py - Configure Django admin for your User model
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from .models import User, UserType, UserStatus


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom admin configuration for User model"""
    
    # Display in list view
    list_display = (
        'email', 'name', 'user_type', 'user_status', 
        'is_active', 'is_email_verified', 'created_at'
    )
    
    # Filters in sidebar
    list_filter = (
        'user_type', 'user_status', 'is_active', 
        'is_email_verified', 'created_at'
    )
    
    # Search fields
    search_fields = ('email', 'name', 'phone')
    
    # Ordering
    ordering = ('-created_at',)
    
    # Fields to display in detail view
    fieldsets = (
        (None, {
            'fields': ('email', 'password')
        }),
        ('Personal Info', {
            'fields': ('name', 'phone', 'profile_image')
        }),
        ('User Type & Status', {
            'fields': ('user_type', 'user_status')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'is_email_verified')
        }),
        ('Important dates', {
            'fields': ('last_login', 'created_at', 'updated_at', 'last_login_at')
        }),
        ('Tokens', {
            'fields': ('reset_token', 'reset_token_expiry', 'email_verification_token', 'email_verification_token_expiry'),
            'classes': ('collapse',)  # Collapsible section
        }),
    )
    
    # Fields to display when adding new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'phone', 'user_type', 'password1', 'password2'),
        }),
    )
    
    # Read-only fields
    readonly_fields = ('created_at', 'updated_at', 'last_login_at', 'id')
    
    # Actions
    actions = ['make_active', 'make_inactive', 'approve_users', 'suspend_users']
    
    def make_active(self, request, queryset):
        """Mark selected users as active"""
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} users marked as active.")
    make_active.short_description = "Mark selected users as active"
    
    def make_inactive(self, request, queryset):
        """Mark selected users as inactive"""
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} users marked as inactive.")
    make_inactive.short_description = "Mark selected users as inactive"
    
    def approve_users(self, request, queryset):
        """Approve selected users"""
        queryset.update(user_status=UserStatus.APPROVED)
        self.message_user(request, f"{queryset.count()} users approved.")
    approve_users.short_description = "Approve selected users"
    
    def suspend_users(self, request, queryset):
        """Suspend selected users"""
        queryset.update(user_status=UserStatus.SUSPENDED, is_active=False)
        self.message_user(request, f"{queryset.count()} users suspended.")
    suspend_users.short_description = "Suspend selected users"


# Customize admin site headers
admin.site.site_header = "Your App Admin"
admin.site.site_title = "Your App Admin Portal"
admin.site.index_title = "Welcome to Your App Administration"