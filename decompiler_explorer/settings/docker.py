import hashlib
import os

from .base import *

with open('/run/secrets/db_superuser_pass', 'r') as f:
    _DB_PASS = f.read()


with open('/run/secrets/worker_auth_token', 'rb') as f:
    WORKER_AUTH_TOKEN_HASH = hashlib.sha256(f.read().strip()).hexdigest()

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'postgres',
        'PASSWORD': _DB_PASS,
        'HOST': 'database',
        'USER': 'postgres',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.PyMemcacheCache',
        'LOCATION': 'memcached:11211',
    }
}

DEFAULT_FILE_STORAGE = os.getenv('DJANGO_FILE_STORAGE', DEFAULT_FILE_STORAGE)
AWS_STORAGE_BUCKET_NAME = os.getenv('AWS_STORAGE_BUCKET_NAME')
AWS_S3_ENDPOINT_URL = os.getenv('AWS_S3_ENDPOINT_URL')
AWS_S3_REGION_NAME = os.getenv('AWS_S3_REGION_NAME')
AWS_IS_GZIPPED = True
GZIP_CONTENT_TYPES = [
    'text/css',
    'text/javascript',
    'application/javascript',
    'application/x-javascript',
    'image/svg',
    'application/octet-stream',
]

USING_S3 = AWS_S3_ENDPOINT_URL is not None

_s3_access_key_id_path = Path('/run/secrets/s3_access_key_id')
_s3_secret_access_key_path = Path('/run/secrets/s3_secret_access_key')

if _s3_access_key_id_path.exists() and _s3_secret_access_key_path.exists():
    AWS_QUERYSTRING_AUTH = True
    AWS_S3_ACCESS_KEY_ID = _s3_access_key_id_path.read_text()
    AWS_S3_SECRET_ACCESS_KEY = _s3_secret_access_key_path.read_text()

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'level': 'INFO' if DEBUG else 'ERROR',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO' if DEBUG else 'ERROR',
        },
    }
}
