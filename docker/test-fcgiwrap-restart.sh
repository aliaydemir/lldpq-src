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
    local attempt previous_master="${1:-}"

    for ((attempt = 1; attempt <= 60; attempt++)); do
        if docker exec "$NAME" bash -ec '
            master=$(ps -eo pid=,pgid=,stat=,comm= | awk '\''
                $1 == $2 && $3 !~ /^[ZX]/ && $4 ~ /(^|\/)fcgiwrap$/ { print $1 }
            '\'')
            [ "$(wc -w <<< "$master")" -eq 1 ]
            [ -z "$1" ] || [ "$master" != "$1" ]
            if [ "${LLDPQ_FCGI_WORKERS:-4}" -gt 1 ]; then
                workers=$(ps -eo ppid=,pgid=,stat=,comm= | awk -v master="$master" '\''
                    $1 == master && $2 == master && $3 !~ /^[ZX]/ && $4 ~ /(^|\/)fcgiwrap$/ { count++ }
                    END { print count + 0 }
                '\'')
                [ "$workers" -eq "${LLDPQ_FCGI_WORKERS:-4}" ]
            fi
            [ -S /var/run/fcgiwrap.socket ]
            [ "$(stat -c "%U:%G:%a" /var/run/fcgiwrap.socket)" = "www-data:www-data:660" ]
            curl -fsS "http://127.0.0.1/auth-api?action=check" |
                jq -e ".authenticated == false" >/dev/null
        ' _ "$previous_master" >/dev/null 2>&1; then
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

# A dead child must restore the configured capacity; a dead master must also
# remove its orphan workers before the replacement binds a fresh socket.
for victim in worker master; do
    old_master=$(docker exec "$NAME" bash -ec '
        master=$(ps -eo pid=,pgid=,stat=,comm= | awk '\''
            $1 == $2 && $3 !~ /^[ZX]/ && $4 ~ /(^|\/)fcgiwrap$/ { print $1 }
        '\'')
        [ "$(wc -w <<< "$master")" -eq 1 ]
        echo "$master"
        if [ "$1" = worker ]; then
            worker=$(pgrep -P "$master" -x fcgiwrap | head -1)
            kill -TERM "$worker"
        else
            kill -KILL "$master"
        fi
    ' _ "$victim")
    wait_for_dynamic_api "$old_master"
    docker exec "$NAME" bash -ec '
        ! ps -eo pgid=,stat= | awk -v old="$1" '\''
            $1 == old && $2 !~ /^[ZX]/ { alive = 1 }
            END { exit !alive }
        '\''
    ' _ "$old_master"
    echo "PASS: $victim loss restored the full CGI pool and removed its old process group"
done

for restart_number in 1 2 3; do
    docker restart "$NAME" >/dev/null
    wait_for_dynamic_api
    echo "PASS: restart $restart_number kept the dynamic CGI API healthy"
done

echo "PASS: fcgiwrap restart regression test"
