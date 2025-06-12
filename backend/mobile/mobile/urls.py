# urls.py - Hybrid configuration with admin and API
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from myapp.views import *
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Django Admin for database management
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/auth/signup/', SignupView.as_view(), name='signup'),
    path('api/auth/login/', LoginView.as_view(), name='login'),
    path('api/auth/logout/', LogoutView.as_view(), name='logout'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Profile endpoints
    path('api/user/profile/', ProfileView.as_view(), name='profile'),
    path('api/user/dashboard/', user_dashboard_data, name='user_dashboard'),

    # Password management
    path('api/auth/password/reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('api/auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('api/auth/password/change/', ChangePasswordView.as_view(), name='change_password'),

    # Email verification
    path('api/auth/email/verify/', EmailVerificationView.as_view(), name='email_verify'),
    path('api/auth/email/resend/', resend_verification_email, name='resend_verification'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)