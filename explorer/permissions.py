import hashlib

from django.conf import settings
from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsWorkerOrAdmin(BasePermission):
    def has_permission(self, request, view):
        if bool(request.user and request.user.is_staff):
            return True

        auth_header = request.META.get('HTTP_X_AUTH_TOKEN')
        if auth_header is None:
            return False

        if settings.DEBUG:
            return True

        hashed_token = hashlib.sha256(auth_header.encode()).hexdigest()

        return hashed_token == settings.WORKER_AUTH_TOKEN_HASH


class ReadOnly(BasePermission):
    def has_permission(self, request, view):
        return request.method in SAFE_METHODS
