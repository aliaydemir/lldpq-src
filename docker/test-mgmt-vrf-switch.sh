#!/bin/bash
# Release check for the LLDPq image on a Cumulus Linux switch.
# Usage: sudo bash docker/test-mgmt-vrf-switch.sh [image-tag]
#
# Run it ON a switch (or any host with a management VRF) after loading the
# image that is about to be released. It starts a temporary container the way
# DOCKER.md documents for a switch (--privileged --network host), checks that
# the services run inside the management VRF and that the host's own network
# state is left alone, removes the container again and compares the host with
# a snapshot taken before the start.
#
# Nothing on the host is configured by this script. It refuses to start while
# another LLDPq container (or anything else) holds the ports the image needs.
#
# Settings (environment):
#   IMAGE             image to test, same as the argument   (lldpq:latest)
#   CONSOLE_PTY_PORT  free loopback port for the console bridge     (18765)
#   MGMT_VRF          name of the management VRF                     (mgmt)
#   INBAND_ADDR       an in-band IPv4 address of this switch (SVI, loopback);
#                     when set, the switch pings it while the container runs
#   INBAND_VRF        VRF that owns INBAND_ADDR            (the default VRF)
#   EXTRA_ARGS        further "docker run" arguments, e.g. "-e LLDPQ_SSHD=no"
#   READY_TIMEOUT     seconds to wait for the ready line              (180)
#   HEALTH_TIMEOUT    seconds to wait for the health check            (150)
#   KEEP=1            leave the container running for inspection
#   LEGACY_RULE=1     LAB ONLY: add the unscoped pref-100 rule of the images
#                     before 4.2.5 first and expect this image to remove it.
#                     The switch stops answering on its in-band IPv4
#                     addresses from that moment until the container is up.
#
# Exit status: 0 every check passed, 1 a check failed, 2 cannot run here.

set -uo pipefail

IMAGE="${1:-${IMAGE:-lldpq:latest}}"
CONSOLE_PTY_PORT="${CONSOLE_PTY_PORT:-18765}"
MGMT_VRF="${MGMT_VRF:-mgmt}"
INBAND_ADDR="${INBAND_ADDR:-}"
INBAND_VRF="${INBAND_VRF:-}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
READY_TIMEOUT="${READY_TIMEOUT:-180}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-150}"
KEEP="${KEEP:-0}"
LEGACY_RULE="${LEGACY_RULE:-0}"

NAME="lldpq-vrf-check-$$-$RANDOM"
LABEL="com.lldpq.regression-test=mgmt-vrf-$NAME"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-vrf-check.XXXXXX") || exit 2

failures=0
checks=0
legacy_rule_added=0
mgmt_table=""

ok()   { checks=$((checks + 1)); printf 'ok    %s\n' "$1"; }
fail() { checks=$((checks + 1)); failures=$((failures + 1)); printf 'FAIL  %s\n' "$1"; }
note() { printf '      %s\n' "$1"; }
cannot_run() { printf 'cannot run: %s\n' "$1" >&2; exit 2; }

# check <description> <command...>: the command's exit status decides.
check() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then ok "$description"; else fail "$description"; fi
}

legacy_rule_present() {
    ip -4 rule show 2>/dev/null |
        grep -Eq "^100:[[:space:]]+from all lookup ($MGMT_VRF|$mgmt_table)[[:space:]]*\$"
}

cleanup() {
    local owned_container

    if [ "$KEEP" != 1 ]; then
        owned_container=$(docker ps -aq \
            --filter "name=^/${NAME}$" \
            --filter "label=$LABEL" 2>/dev/null || true)
        if [ -n "$owned_container" ]; then
            docker rm -f "$owned_container" >/dev/null 2>&1 || true
        fi
    fi
    # Never leave the rule this script added: it is the outage itself.
    if [ "$legacy_rule_added" = 1 ] && [ -n "$mgmt_table" ] && legacy_rule_present; then
        if ip -4 rule del pref 100 table "$mgmt_table" 2>/dev/null; then
            printf 'removed the pref-100 rule this check had added\n' >&2
        else
            printf 'WARNING: remove the rule by hand: ip -4 rule del pref 100 table %s\n' \
                "$mgmt_table" >&2
        fi
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Host state the container must not change. Counters and other values that
# move by themselves are left out so that an unchanged host compares equal.
snapshot() {
    local dir="$1"

    mkdir -p "$dir"
    ip -4 rule show                          > "$dir/rules-ipv4" 2>&1
    ip -6 rule show                          > "$dir/rules-ipv6" 2>&1
    ip -4 route show table "$mgmt_table"     > "$dir/routes-ipv4-$MGMT_VRF" 2>&1
    ip -6 route show table "$mgmt_table"     > "$dir/routes-ipv6-$MGMT_VRF" 2>&1
    ip -o link show | awk '{
            master = ""
            for (i = 3; i < NF; i++) if ($i == "master") master = $(i + 1)
            print $2, master
        }' | sort                            > "$dir/links" 2>&1
    ip -o addr show | awk '{print $2, $3, $4}' | sort > "$dir/addresses" 2>&1
    sysctl -a 2>/dev/null | grep -E '^net\.' |
        grep -Ev '(conntrack_count|\.stats\.|neigh\..*\.(gc_|base_reachable)|route\.(gc_|flush)|nf_log|\.stable_secret)' |
        sort                                 > "$dir/sysctl-net"
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save 2>/dev/null | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]//' \
                                             > "$dir/iptables"
    fi
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save 2>/dev/null | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]//' \
                                             > "$dir/ip6tables"
    fi
    # Routes outside the management table change with the fabric; they are
    # reported, not judged.
    ip -4 route show table all 2>/dev/null | sort > "$dir/info-routes-ipv4-all"
}

compare_snapshots() {
    local before="$1" after="$2" label="$3" file name

    for file in "$before"/*; do
        name=$(basename "$file")
        case "$name" in
            info-*)
                if ! cmp -s "$file" "$after/$name"; then
                    note "$label: $name differs (not judged: routes follow the fabric)"
                fi
                ;;
            *)
                if cmp -s "$file" "$after/$name"; then
                    ok "$label: $name unchanged"
                else
                    fail "$label: $name changed"
                    diff "$file" "$after/$name" | sed 's/^/        /' | head -20
                fi
                ;;
        esac
    done
}

inband_ping() {
    if [ -n "$INBAND_VRF" ]; then
        ip vrf exec "$INBAND_VRF" ping -c 2 -W 1 "$INBAND_ADDR"
    else
        ping -c 2 -W 1 "$INBAND_ADDR"
    fi
}

port_in_use() {
    ss -Htln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"
}

wait_for_log_line() {
    local waited=0

    while [ "$waited" -lt "$READY_TIMEOUT" ]; do
        if docker logs "$NAME" 2>&1 | grep -q 'LLDPq is ready'; then
            return 0
        fi
        if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ]; then
            return 1
        fi
        sleep 3
        waited=$((waited + 3))
    done
    return 1
}

wait_for_health() {
    local waited=0 health=""

    while [ "$waited" -lt "$HEALTH_TIMEOUT" ]; do
        health=$(docker inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null)
        [ "$health" = healthy ] && return 0
        sleep 5
        waited=$((waited + 5))
    done
    return 1
}

# ─── Can this run here? ───
[ "$(id -u)" -eq 0 ] || cannot_run "run it as root: sudo bash $0 [image-tag]"
command -v docker >/dev/null 2>&1 || cannot_run "docker is not installed"
docker image inspect "$IMAGE" >/dev/null 2>&1 || cannot_run "image $IMAGE is not loaded"
mgmt_table=$(ip vrf show "$MGMT_VRF" 2>/dev/null | awk -v vrf="$MGMT_VRF" '$1 == vrf {print $2; exit}')
case "$mgmt_table" in
    ''|*[!0-9]*) cannot_run "this host has no VRF named $MGMT_VRF" ;;
esac
for port in 80 "$CONSOLE_PTY_PORT"; do
    if port_in_use "$port"; then
        cannot_run "TCP port $port is in use (stop the running LLDPq container first)"
    fi
done
if legacy_rule_present; then
    cannot_run "the unscoped pref-100 rule is already on this host; clear it first (DOCKER.md, Management VRF)"
fi

printf 'image:    %s (%s)\n' "$IMAGE" "$(docker image inspect -f '{{.Id}}' "$IMAGE" | cut -c8-19)"
printf 'host:     %s, VRF %s is table %s\n' "$(uname -r)" "$MGMT_VRF" "$mgmt_table"

snapshot "$WORK/before"
if [ -n "$INBAND_ADDR" ]; then
    check "before the start: the host answers on its in-band address $INBAND_ADDR" inband_ping
fi

if [ "$LEGACY_RULE" = 1 ]; then
    printf 'LEGACY_RULE=1: adding the unscoped pref-100 rule of the old images\n'
    if ip -4 rule add pref 100 table "$mgmt_table"; then
        legacy_rule_added=1
    else
        cannot_run "could not add the legacy rule"
    fi
fi

# ─── Start the image the documented way ───
# shellcheck disable=SC2086  # EXTRA_ARGS is a list of arguments by design
if ! docker run -d --name "$NAME" --label "$LABEL" \
        --privileged --restart no --network host \
        -e CONSOLE_PTY_PORT="$CONSOLE_PTY_PORT" \
        -e LLDPQ_DHCP_MODE=disabled -e DHCP_AUTOSTART=false \
        $EXTRA_ARGS "$IMAGE" >/dev/null; then
    fail "the container starts"
    exit 1
fi

if wait_for_log_line; then
    ok "the container reports ready"
else
    fail "the container reports ready within ${READY_TIMEOUT}s"
    docker logs "$NAME" 2>&1 | tail -15 | sed 's/^/        /'
    exit 1
fi
docker logs "$NAME" > "$WORK/log" 2>&1
grep -E 'VRF|ERROR' "$WORK/log" | sed 's/^/      log: /'

# ─── The services run inside the management VRF ───
check "log: services run inside the $MGMT_VRF VRF" \
    grep -q "$MGMT_VRF VRF detected (table $mgmt_table) — services run inside it" "$WORK/log"
if grep -q 'outbound via' "$WORK/log"; then
    fail "log: this image still adds the routing rule (outbound via $MGMT_VRF)"
fi
if grep -q 'VRF not entered' "$WORK/log"; then
    fail "log: the image did not enter the VRF"
fi
if [ "$LEGACY_RULE" = 1 ]; then
    check "log: the leftover rule was removed" \
        grep -q "removed the unscoped $MGMT_VRF VRF rule (pref 100)" "$WORK/log"
fi
if legacy_rule_present; then
    fail "host: no unscoped pref-100 rule to the $MGMT_VRF table"
else
    ok "host: no unscoped pref-100 rule to the $MGMT_VRF table"
fi

marker=$(docker exec "$NAME" cat /run/lldpq-service-vrf 2>/dev/null)
if [ "$marker" = "$MGMT_VRF" ]; then ok "container: service VRF record says $MGMT_VRF"
else fail "container: service VRF record says '$marker', expected $MGMT_VRF"; fi

pid1_vrf=$(docker exec "$NAME" ip vrf identify 1 2>/dev/null)
if [ "$pid1_vrf" = "$MGMT_VRF" ]; then ok "container: PID 1 runs in VRF $MGMT_VRF"
else fail "container: PID 1 runs in VRF '$pid1_vrf', expected $MGMT_VRF"; fi

if ss -Htln 2>/dev/null | awk '{print $4}' | grep -Eq "%$MGMT_VRF:80\$"; then
    ok "host: the web listener is bound to the $MGMT_VRF VRF"
else
    fail "host: the web listener is bound to the $MGMT_VRF VRF"
    ss -Htln 2>/dev/null | awk '{print $4}' | grep -E ':80$' | sed 's/^/        /'
fi

code=$(ip vrf exec "$MGMT_VRF" curl -sS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null)
if [ "$code" = 200 ]; then ok "host: the documented start check answers HTTP 200"
else fail "host: the documented start check answers HTTP '$code', expected 200"; fi

# A plain `docker exec` starts outside the VRF; the image's own curl has to
# join the services or the documented update steps roll a good image back.
code=$(docker exec "$NAME" curl -sS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1/login.html 2>/dev/null)
if [ "$code" = 200 ]; then ok "container: curl started with docker exec reaches the web service"
else fail "container: curl started with docker exec got HTTP '$code', expected 200"; fi

check "container: the readiness probe of the update steps passes" \
    docker exec "$NAME" sh -c '
        if command -v lldpq-vrf >/dev/null 2>&1; then
            exec lldpq-vrf curl -fsS http://127.0.0.1/login.html
        fi
        exec curl -fsS http://127.0.0.1/login.html'

if wait_for_health; then
    ok "container: the health check reports healthy"
else
    fail "container: the health check reports healthy within ${HEALTH_TIMEOUT}s"
fi

if [ -n "$INBAND_ADDR" ]; then
    check "while running: the host answers on its in-band address $INBAND_ADDR" inband_ping
fi

snapshot "$WORK/running"
compare_snapshots "$WORK/before" "$WORK/running" "while running"

# ─── Removing the container leaves the host as it was ───
if [ "$KEEP" = 1 ]; then
    printf 'KEEP=1: container %s is left running; remove it with: docker rm -f %s\n' \
        "$NAME" "$NAME"
else
    check "the container is removed" docker rm -f "$NAME"
    snapshot "$WORK/after"
    compare_snapshots "$WORK/before" "$WORK/after" "after removal"
    if [ -n "$INBAND_ADDR" ]; then
        check "after removal: the host answers on its in-band address $INBAND_ADDR" inband_ping
    fi
fi

printf '\n%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
