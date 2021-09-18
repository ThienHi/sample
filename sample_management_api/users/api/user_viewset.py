from django import http
from django.contrib import admin
from rest_framework import viewsets, permissions, status
from sample_management_api.users.api.serializers import UserSerializer, UpdateUserStatusSerializer
from sample_management_api.users.models import User
from rest_framework.decorators import action
from rest_framework.response import Response
from sample_management_api.utils.pagination import Pagination


class UserViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    permission_classes = (permissions.IsAuthenticated, )
    pagination_class = Pagination

    # lookup_field = "username"

    def get_queryset(self, *args, **kwargs):
        return self.queryset.filter(id=self.request.user.id)

    def list(self, request, *args, **kwargs):
        queryset = User.objects.all().exclude(email="admin@gmail.com")
        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["GET"])
    def me(self, request):
        serializer = UserSerializer(request.user, context={"request": request})
        return Response(status=status.HTTP_200_OK, data=serializer.data)

    def create(self, request, *args, **kwargs):
        sz = UserSerializer(data=request.data)
        sz.is_valid(raise_exception=True)
        user = User.objects.create(
            email=sz.data["email"],
            username=sz.data["email"],
            first_name=sz.data["first_name"],
            last_name=sz.data["last_name"],
            status=sz.data["status"],
            role=sz.data["role"],
        )
        user.set_password(request.data["password"])
        user.save()
        return Response(data=sz.data, status=status.HTTP_201_CREATED)

    @action(methods=["post"], detail=False, url_path="status")
    def update_status(self, request, pk=None):
        sz = UpdateUserStatusSerializer(data=request.data)
        if sz.is_valid(raise_exception=True):
            if sz.data["apply_all"]:
                User.objects.exclude(pk=request.user.id).update(status=request.data.get('status'))
            else:
                User.objects.filter(id__in=request.data.get('users')).update(status=request.data.get('status'))
        return Response(status=status.HTTP_200_OK)
