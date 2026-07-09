#!/bin/bash
# Regression test for the Docker fcgiwrap socket lifecycle.
# Usage: sudo bash docker/test-fcgiwrap-restart.sh [image-tag]

set -euo pipefail

IMAGE="${1:-lldpq:latest}"
NAME="lldpq-fcgiwrap-restart-test-$$-$RANDOM"
LABEL="com.lldpq.regression-test=fcgiwrap-restart-$NAME"

cleanup() {
    local owned_container

    owned_container=$(docker ps -aq \
        --filter "name=^/${NAME}$" \
        --filter "label=$LABEL" 2>/dev/null || true)
    if [ -n "$owned_container" ]; then
        docker rm -f "$owned_container" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_dynamic_api() {
    local attempt

    for ((attempt = 1; attempt <= 60; attempt++)); do
        if docker exec "$NAME" bash -ec '
            [ "$(pgrep -xc fcgiwrap)" -eq 1 ]
            [ -S /var/run/fcgiwrap.socket ]
            [ "$(stat -c "%U:%G:%a" /var/run/fcgiwrap.socket)" = "www-data:www-data:660" ]
            curl -fsS "http://127.0.0.1/auth-api?action=check" |
                jq -e ".authenticated == false" >/dev/null
        ' >/dev/null 2>&1; then
            return 0
        fi

        if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)" != true ]; then
            break
        fi
        sleep 2
    done

    echo "ERROR: dynamic CGI API did not become healthy within 120 seconds" >&2
    docker logs "$NAME" >&2 || true
    return 1
}

docker image inspect "$IMAGE" >/dev/null
docker run -d \
    --name "$NAME" \
    --label "$LABEL" \
    --privileged \
    --restart=no \
    --network none \
    -e LLDPQ_DHCP_MODE=disabled \
    -e DHCP_AUTOSTART=false \
    "$IMAGE" >/dev/null

wait_for_dynamic_api

for restart_number in 1 2 3; do
    docker restart "$NAME" >/dev/null
    wait_for_dynamic_api
    echo "PASS: restart $restart_number kept the dynamic CGI API healthy"
done

echo "PASS: fcgiwrap restart regression test"
