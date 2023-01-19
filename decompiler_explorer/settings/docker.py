import hashlib
import os

from .base import *

with open('/run/secrets/db_superuser_pass', 'r') as f:
    _DB_PASS = f.read()


with open('/run/secrets/worker_auth_token', 'rb') as f:
    WORKER_AUTH_TOKEN_HASH = hashlib.sha256(f.read()).hexdigest()

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'postgres',
        'PASSWORD': _DB_PASS,
        'HOST': 'database',
        'USER': 'postgres',
    }
}

DEFAULT_FILE_STORAGE = os.getenv('DJANGO_FILE_STORAGE', DEFAULT_FILE_STORAGE)
AWS_STORAGE_BUCKET_NAME = os.getenv('AWS_STORAGE_BUCKET_NAME')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'level': 'ERROR',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'ERROR',
        },
    }
}
