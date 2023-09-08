import hashlib

from django.conf import settings

def is_request_from_worker(request):
    auth_header = request.META.get('HTTP_X_AUTH_TOKEN')
    if auth_header is None:
        return False
    if settings.DEBUG:
        return True
    hashed_token = hashlib.sha256(auth_header.encode()).hexdigest()
    return hashed_token == settings.WORKER_AUTH_TOKEN_HASH
