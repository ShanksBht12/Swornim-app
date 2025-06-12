# models.py
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone
import uuid


class UserType(models.TextChoices):
    CLIENT = 'client', 'Client'
    PHOTOGRAPHER = 'photographer', 'Photographer'
    MAKEUP_ARTIST = 'makeupArtist', 'Makeup Artist'
    DECORATOR = 'decorator', 'Decorator'
    VENUE = 'venue', 'Venue Owner'
    CATERER = 'caterer', 'Caterer'


class UserStatus(models.TextChoices):
    PENDING = 'pending', 'Pending'
    APPROVED = 'approved', 'Approved'
    ACTIVE = 'active', 'Active'
    SUSPENDED = 'suspended', 'Suspended'
    REJECTED = 'rejected', 'Rejected'
    INACTIVE = 'inactive', 'Inactive'


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_email_verified', True)
        extra_fields.setdefault('user_type', UserType.CLIENT)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    user_type = models.CharField(max_length=20, choices=UserType.choices, default=UserType.CLIENT)
    user_status = models.CharField(max_length=20, choices=UserStatus.choices, default=UserStatus.PENDING)
    
    # Add related_name to resolve conflicts
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        related_name='custom_user_set',
        help_text='The groups this user belongs to.'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        related_name='custom_user_set',
        help_text='Specific permissions for this user.'
    )
    
    # Auth fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    
    # Password reset fields
    reset_token = models.CharField(max_length=255, null=True, blank=True)
    reset_token_expiry = models.DateTimeField(null=True, blank=True)
    
    # Email verification fields (separate from password reset)
    email_verification_token = models.CharField(max_length=255, null=True, blank=True)
    email_verification_token_expiry = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_at = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.name} ({self.email})"

    def can_login(self):
        """Check if user can login"""
        return self.is_active and self.is_email_verified

    def is_password_reset_token_valid(self):
        """Check if password reset token is valid"""
        return (self.reset_token and 
                self.reset_token_expiry and 
                self.reset_token_expiry > timezone.now())

    def is_email_verification_token_valid(self):
        """Check if email verification token is valid"""
        return (self.email_verification_token and 
                self.email_verification_token_expiry and 
                self.email_verification_token_expiry > timezone.now())

    def can_access_service_provider_features(self):
        """Check if user can access service provider features"""
        return self.user_type != UserType.CLIENT and self.is_active

    def get_user_role_display_name(self):
        """Get user role display name"""
        return dict(UserType.choices)[self.user_type]

    def clear_password_reset_token(self):
        """Clear password reset token and expiry"""
        self.reset_token = None
        self.reset_token_expiry = None

    def clear_email_verification_token(self):
        """Clear email verification token and expiry"""
        self.email_verification_token = None
        self.email_verification_token_expiry = None

    def to_safe_dict(self):
        """Return safe user data (without sensitive fields)"""
        return {
            'id': str(self.id),
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'profile_image': self.profile_image.url if self.profile_image else None,
            'user_type': self.user_type,
            'user_status': self.user_status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'is_active': self.is_active,
            'is_email_verified': self.is_email_verified,
            'can_access_service_provider_features': self.can_access_service_provider_features(),
            'user_role_display': self.get_user_role_display_name(),
        }