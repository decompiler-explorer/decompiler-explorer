#!/bin/bash

pipenv run ./manage.py migrate -v 0
pipenv run ./manage.py collectstatic -v 0 --no-input --clear
pipenv run ./manage.py ensure_admin

exec pipenv run "$@"
