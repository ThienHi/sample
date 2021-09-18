import datetime
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.db.models import Q
from django.utils.text import gettext_lazy as _
from django.utils.translation import activate
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.encoding import force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator


User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User

        fields = ["id", "first_name", "last_name", "email", "role", "status", "last_login", "password", "password2"]
        extra_kwargs = {
            "url": {"view_name": "api:user-detail", "lookup_field": "username"},
            "email": {"required": True},
            "first_name": {"required": True},
            "last_name": {"required": True},
            "role": {"required": True},
            "status": {"required": True},
        }

    def validate(self, attrs):
        user = User.objects.filter(
            Q(email=attrs["email"]) | Q(username=attrs["email"])
        ).first()

        if user:
            raise serializers.ValidationError({"email": "Email is taken"})

        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {"bad_token": _("Token is invalid or expired")}

    def validate(self, attrs):
        self.token = attrs["refresh"]
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail("bad_token")


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        print(self.user)
        if self.user.status.lower() == "active":
            data["refresh"] = str(refresh)
            data["access"] = str(refresh.access_token)
            user = User.objects.get(email=attrs['username'])
            user.last_login = datetime.datetime.now()
            user.save()
            return data
        else:
            raise serializers.ValidationError({"User": "User is suspended"})

# class RegisterSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(
#         required=True, validators=[UniqueValidator(queryset=User.objects.all())]
#     )
#     password = serializers.CharField(
#         write_only=True, required=True, validators=[validate_password]
#     )
#     password2 = serializers.CharField(write_only=True, required=True)
#     first_name = serializers.CharField(required=False)
#     last_name = serializers.CharField(required=True)
#     role = serializers.CharField(required=True)
#     status = serializers.CharField(required=True)

#     class Meta:
#         model = User
#         fields = (
#             "password",
#             "password2",
#             "email",
#             "first_name",
#             "last_name",
#             "role",
#             "status"

#         )

#     def validate(self, attrs):
#         user = User.objects.filter(
#             Q(email=attrs["email"]) | Q(username=attrs["email"])
#         ).first()

#         if user:
#             raise serializers.ValidationError({"email": "Email is taken"})

#         if attrs["password"] != attrs["password2"]:
#             raise serializers.ValidationError(
#                 {"password": "Password fields didn't match."}
#             )
#         return attrs

#     def create(self, validated_data):
#         user = User.objects.create(
#             email=validated_data["email"],
#             username=validated_data["email"],
#             first_name=validated_data.get("first_name", None),
#             last_name=validated_data.get("last_name", None),
#             status=validated_data.get("status", None),
#             role=validated_data.get("role", None),
#         )

#         user.set_password(validated_data["password"])
#         user.save()

#         return user


class UpdateUserStatusSerializer(serializers.Serializer):
    users = serializers.ListField(required=True)
    status = serializers.CharField(required=True)
    apply_all = serializers.BooleanField(required=True)

    class Meta:
        fields = ['users', 'status', 'apply_all']

    def validate(self, attrs):
        users = attrs.get('users')
        status = attrs.get('status')

        if status.lower() not in ['active', 'suspended']:
            raise serializers.ValidationError({"status": "status is invalid"})

        for user in users:
            if not User.objects.get(pk=user):
                raise serializers.ValidationError({"users": user + " is invalid UserID"})
        return super().validate(attrs)


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)
