# views.py
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.contrib.auth import login, logout
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
import secrets
import uuid

from myapp.models import User
from myapp.serializers import (
    UserSignupSerializer, UserLoginSerializer, UserSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    EmailVerificationSerializer, ChangePasswordSerializer
)


def get_tokens_for_user(user):
    """Generate JWT tokens for user"""
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class SignupView(generics.CreateAPIView):
    """User registration endpoint"""
    queryset = User.objects.all()
    serializer_class = UserSignupSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Create user
        user = serializer.save()
        
        # Generate email verification token
        verification_token = str(uuid.uuid4())
        user.email_verification_token = verification_token
        user.email_verification_token_expiry = timezone.now() + timezone.timedelta(days=1)
        user.save()
        
        # Send verification email
        self.send_verification_email(user, verification_token)
        
        return Response({
            'message': 'Account created successfully. Please check your email to verify your account.',
            'user': UserSerializer(user, context={'request': request}).data
        }, status=status.HTTP_201_CREATED)
    
    def send_verification_email(self, user, token):
        """Send email verification email"""
        try:
            subject = 'Verify Your Email Address'
            verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}"
            
            html_message = render_to_string('emails/email_verification.html', {
                'user': user,
                'verification_url': verification_url,
            })
            
            send_mail(
                subject=subject,
                message=f'Please click the following link to verify your email: {verification_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception as e:
            print(f"Failed to send verification email: {e}")


class LoginView(generics.GenericAPIView):
    """User login endpoint"""
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        
        # Update last login
        user.last_login_at = timezone.now()
        user.save(update_fields=['last_login_at'])
        
        # Generate JWT tokens
        tokens = get_tokens_for_user(user)
        
        # Login user (for session-based auth if needed)
        login(request, user)
        
        return Response({
            'message': 'Login successful',
            'user': UserSerializer(user, context={'request': request}).data,
            'tokens': tokens,
            'can_access_service_provider_features': user.can_access_service_provider_features()
        }, status=status.HTTP_200_OK)


class LogoutView(generics.GenericAPIView):
    """User logout endpoint"""
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        try:
            # Get refresh token from request
            refresh_token = request.data.get("refresh")
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            # Logout user
            logout(request)
            
            return Response({
                'message': 'Logout successful'
            }, status=status.HTTP_200_OK)
            
        except TokenError:
            return Response({
                'error': 'Invalid token'
            }, status=status.HTTP_400_BAD_REQUEST)


class TokenRefreshView(generics.GenericAPIView):
    """Refresh JWT token endpoint"""
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({
                    'error': 'Refresh token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            refresh = RefreshToken(refresh_token)
            access_token = refresh.access_token
            
            return Response({
                'access': str(access_token),
            }, status=status.HTTP_200_OK)
            
        except TokenError as e:
            return Response({
                'error': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)


class ProfileView(generics.RetrieveUpdateAPIView):
    """User profile endpoint"""
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_object(self):
        return self.request.user


class PasswordResetRequestView(generics.GenericAPIView):
    """Request password reset endpoint"""
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.context['user']
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        user.reset_token = reset_token
        user.reset_token_expiry = timezone.now() + timezone.timedelta(hours=1)
        user.save(update_fields=['reset_token', 'reset_token_expiry'])
        
        # Send reset email
        self.send_reset_email(user, reset_token)
        
        return Response({
            'message': 'Password reset email sent. Please check your email.'
        }, status=status.HTTP_200_OK)
    
    def send_reset_email(self, user, token):
        """Send password reset email"""
        try:
            subject = 'Reset Your Password'
            reset_url = f"{settings.FRONTEND_URL}/reset-password/{token}"
            
            html_message = render_to_string('emails/password_reset.html', {
                'user': user,
                'reset_url': reset_url,
            })
            
            send_mail(
                subject=subject,
                message=f'Please click the following link to reset your password: {reset_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception as e:
            print(f"Failed to send reset email: {e}")


class PasswordResetConfirmView(generics.GenericAPIView):
    """Confirm password reset endpoint"""
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data['user']
        new_password = serializer.validated_data['password']
        
        # Update password
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        user.save(update_fields=['password', 'reset_token', 'reset_token_expiry'])
        
        return Response({
            'message': 'Password reset successful. You can now login with your new password.'
        }, status=status.HTTP_200_OK)


class EmailVerificationView(generics.GenericAPIView):
    """Email verification endpoint"""
    serializer_class = EmailVerificationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.context['user']
        
        # Verify email
        user.is_email_verified = True
        user.email_verification_token = None
        user.email_verification_token_expiry = None
        user.save(update_fields=['is_email_verified', 'email_verification_token', 'email_verification_token_expiry'])
        
        return Response({
            'message': 'Email verified successfully. You can now login to your account.'
        }, status=status.HTTP_200_OK)


class ChangePasswordView(generics.GenericAPIView):
    """Change password endpoint"""
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        new_password = serializer.validated_data['new_password']
        
        # Update password
        user.set_password(new_password)
        user.save(update_fields=['password'])
        
        # Generate new tokens after password change
        tokens = get_tokens_for_user(user)
        
        return Response({
            'message': 'Password changed successfully.',
            'tokens': tokens  # Return new tokens since password changed
        }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification_email(request):
    """Resend email verification"""
    email = request.data.get('email')
    
    if not email:
        return Response({
            'error': 'Email is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email.lower(), is_email_verified=False)
        
        # Generate new verification token
        verification_token = str(uuid.uuid4())
        user.email_verification_token = verification_token
        user.email_verification_token_expiry = timezone.now() + timezone.timedelta(days=1)
        user.save(update_fields=['email_verification_token', 'email_verification_token_expiry'])
        
        # Send verification email
        send_verification_email(user, verification_token)
        
        return Response({
            'message': 'Verification email sent successfully.'
        }, status=status.HTTP_200_OK)
        
    except User.DoesNotExist:
        return Response({
            'error': 'No unverified account found with this email.'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_dashboard_data(request):
    """Get dashboard data for user"""
    user = request.user
    
    return Response({
        'user': UserSerializer(user, context={'request': request}).data,
        'can_access_service_provider_features': user.can_access_service_provider_features(),
        'user_role_display': user.get_user_role_display_name(),
        'account_status': {
            'is_active': user.is_active,
            'is_email_verified': user.is_email_verified,
            'user_status': user.user_status,
        }
    }, status=status.HTTP_200_OK)


def send_verification_email(user, token):
    """Helper function to send verification email"""
    try:
        subject = 'Verify Your Email Address'
        verification_url = f"{settings.FRONTEND_URL}/verify-email/{token}"
        
        html_message = render_to_string('emails/email_verification.html', {
            'user': user,
            'verification_url': verification_url,
        })
        
        send_mail(
            subject=subject,
            message=f'Please click the following link to verify your email: {verification_url}',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False,
        )
    except Exception as e:
        print(f"Failed to send verification email: {e}")