# auth_utils.py
import secrets
import hashlib
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from .models import User, UserType


class AuthUtils:
    """Utility class for authentication operations"""
    
    @staticmethod
    def generate_secure_token():
        """Generate a secure random token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_password_with_salt(password, salt=None):
        """Hash password with salt (for compatibility with Flutter app)"""
        if salt is None:
            salt = settings.SECRET_KEY[:16]  # Use part of secret key as salt
        
        combined = password + salt
        return hashlib.sha256(combined.encode()).hexdigest()
    
    @staticmethod
    def verify_password_with_salt(password, hashed_password, salt=None):
        """Verify password with salt"""
        if salt is None:
            salt = settings.SECRET_KEY[:16]
        
        return AuthUtils.hash_password_with_salt(password, salt) == hashed_password
    
    @staticmethod
    def can_access_service_provider_features(user):
        """Check if user can access service provider features"""
        return user.user_type != UserType.CLIENT and user.is_active
    
    @staticmethod
    def get_user_role_display_name(user_type):
        """Get user role display name"""
        role_mapping = {
            UserType.CLIENT: 'Client',
            UserType.PHOTOGRAPHER: 'Photographer',
            UserType.MAKEUP_ARTIST: 'Makeup Artist',
            UserType.DECORATOR: 'Decorator',
            UserType.VENUE: 'Venue Owner',
            UserType.CATERER: 'Caterer',
        }
        return role_mapping.get(user_type, 'Unknown')
    
    @staticmethod
    def send_email_notification(user, email_type, **kwargs):
        """Send email notification to user"""
        email_templates = {
            'welcome': {
                'subject': 'Welcome to Our Platform!',
                'template': 'emails/welcome.html'
            },
            'verification': {
                'subject': 'Verify Your Email Address',
                'template': 'emails/email_verification.html'
            },
            'password_reset': {
                'subject': 'Reset Your Password',
                'template': 'emails/password_reset.html'
            },
            'password_changed': {
                'subject': 'Password Changed Successfully',
                'template': 'emails/password_changed.html'
            },
            'account_approved': {
                'subject': 'Account Approved',
                'template': 'emails/account_approved.html'
            },
            'account_suspended': {
                'subject': 'Account Suspended',
                'template': 'emails/account_suspended.html'
            }
        }
        
        if email_type not in email_templates:
            raise ValueError(f"Unknown email type: {email_type}")
            
        template_info = email_templates[email_type]
        
        # Prepare context for email template
        context = {
            'user': user,
            'site_name': settings.SITE_NAME,
            'site_url': settings.SITE_URL,
            **kwargs  # Include any additional template variables
        }
        
        # Render email content from template
        html_content = render_to_string(template_info['template'], context)
        
        # Send email
        try:
            send_mail(
                subject=template_info['subject'],
                message='',  # Empty plain text message
                html_message=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False
            )
            return True
        except Exception as e:
            # Log the error in production
            print(f"Failed to send email: {str(e)}")  # For development
            return False