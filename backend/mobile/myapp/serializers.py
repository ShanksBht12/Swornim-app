# serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User, UserType


class UserSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ('name', 'email', 'phone', 'user_type', 'password', 'password_confirm')

    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower()

    def validate_phone(self, value):
        """Validate phone number"""
        # Remove any non-digit characters
        phone = ''.join(filter(str.isdigit, value))
        if len(phone) < 10:
            raise serializers.ValidationError("Phone number must be at least 10 digits.")
        return phone

    def validate_user_type(self, value):
        """Validate user type"""
        if value not in [choice.value for choice in UserType]:
            raise serializers.ValidationError("Invalid user type.")
        return value

    def validate(self, attrs):
        """Validate password confirmation"""
        password = attrs.get('password')
        password_confirm = attrs.pop('password_confirm', None)

        if password != password_confirm:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match.'
            })

        # Validate password strength
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({
                'password': list(e.messages)
            })

        return attrs

    def create(self, validated_data):
        """Create new user"""
        password = validated_data.pop('password')
        user = User.objects.create_user(
            password=password,
            **validated_data
        )
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Normalize email
            email = email.lower()
            
            # Check if user exists
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError({
                    'email': 'No account found with this email address.'
                })

            # Check if user can login
            if not user.can_login():
                if not user.is_active:
                    raise serializers.ValidationError({
                        'non_field_errors': 'Account is inactive. Please contact support.'
                    })
                elif not user.is_email_verified:
                    raise serializers.ValidationError({
                        'non_field_errors': 'Email address is not verified. Please check your email for verification link.'
                    })

            # Authenticate user
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password
            )

            if not user:
                raise serializers.ValidationError({
                    'password': 'Invalid password.'
                })

            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError({
                'non_field_errors': 'Must include email and password.'
            })


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user profile data"""
    user_role_display = serializers.CharField(source='get_user_role_display_name', read_only=True)
    profile_image_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            'id', 'name', 'email', 'phone', 'profile_image_url', 
            'user_type', 'user_role_display', 'user_status',
            'created_at', 'updated_at', 'is_active', 'is_email_verified'
        )
        read_only_fields = (
            'id', 'created_at', 'updated_at', 'user_status', 
            'is_active', 'is_email_verified'
        )

    def get_profile_image_url(self, obj):
        if obj.profile_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_image.url)
            return obj.profile_image.url
        return None


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """Validate that user exists with this email"""
        email = value.lower()
        try:
            user = User.objects.get(email=email, is_active=True)
            self.context['user'] = user
            return email
        except User.DoesNotExist:
            raise serializers.ValidationError("No active account found with this email address.")


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(
        min_length=8,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        style={'input_type': 'password'}
    )

    def validate(self, attrs):
        token = attrs.get('token')
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')

        # Check if passwords match
        if password != password_confirm:
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match.'
            })

        # Validate password strength
        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError({
                'password': list(e.messages)
            })

        # Find user with valid token
        try:
            user = User.objects.get(reset_token=token)
            if not user.is_password_reset_token_valid():
                raise serializers.ValidationError({
                    'token': 'Password reset token is invalid or has expired.'
                })
            attrs['user'] = user
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'token': 'Invalid password reset token.'
            })

        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        """Validate email verification token"""
        # This would typically involve checking a verification token
        # For now, we'll use a simple approach
        try:
            user = User.objects.get(reset_token=value, is_email_verified=False)
            self.context['user'] = user
            return value
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid verification token.")


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(style={'input_type': 'password'})
    new_password = serializers.CharField(
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(style={'input_type': 'password'})

    def validate_old_password(self, value):
        """Validate current password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')

        if new_password != new_password_confirm:
            raise serializers.ValidationError({
                'new_password_confirm': 'New passwords do not match.'
            })

        # Validate password strength
        try:
            validate_password(new_password)
        except ValidationError as e:
            raise serializers.ValidationError({
                'new_password': list(e.messages)
            })

        return attrs