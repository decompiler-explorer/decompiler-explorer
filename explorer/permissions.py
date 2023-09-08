from rest_framework.permissions import BasePermission, SAFE_METHODS

from decompiler_explorer.utils import is_request_from_worker

class IsWorkerOrAdmin(BasePermission):
    def has_permission(self, request, view):
        if bool(request.user and request.user.is_staff):
            return True
        return is_request_from_worker(request)


class ReadOnly(BasePermission):
    def has_permission(self, request, view):
        return request.method in SAFE_METHODS
