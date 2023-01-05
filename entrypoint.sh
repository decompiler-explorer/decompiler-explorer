#!/bin/bash


health_check () {
    pipenv run ./manage.py check --database default;
    return $?;
}

HEALTH_CHECK_INTERVAL=5;
HEALTH_CHECK_ATTEMPTS=0;
HEALTH_CHECK_ATTEMPT_LIMIT=5;
while ! health_check; do
    HEALTH_CHECK_ATTEMPTS=$((HEALTH_CHECK_ATTEMPTS + 1));
    echo "Health check attempt ${HEALTH_CHECK_ATTEMPTS} failed, retrying in ${HEALTH_CHECK_INTERVAL} seconds...";
    if [ "$HEALTH_CHECK_ATTEMPTS" -ge "$HEALTH_CHECK_ATTEMPT_LIMIT" ]; then
        echo "Exceeded number of health check attempts, exiting";
        exit 1;
    fi;
    sleep $HEALTH_CHECK_INTERVAL;
done

set -e

pipenv run ./manage.py migrate -v 0
pipenv run ./manage.py collectstatic -v 0 --no-input --clear
pipenv run ./manage.py ensure_admin

exec pipenv run "$@"
