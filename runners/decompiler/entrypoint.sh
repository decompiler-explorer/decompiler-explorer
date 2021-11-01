#!/bin/sh
set -e

until curl -fs ${SERVER:-http://explorer:8000} > /dev/null; do
  >&2 echo "Server is unavailable - sleeping"
  sleep 1
done
  
>&2 echo "Server is up"
exec python -u ./runner_generic.py "$@"
