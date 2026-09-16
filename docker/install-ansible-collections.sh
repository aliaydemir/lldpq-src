#!/bin/sh
set -eu

max_attempts="${ANSIBLE_GALAXY_MAX_ATTEMPTS:-4}"
api_timeout="${ANSIBLE_GALAXY_TIMEOUT:-180}"
retry_delay="${ANSIBLE_GALAXY_RETRY_DELAY:-15}"

for value in "$max_attempts" "$api_timeout" "$retry_delay"; do
    case "$value" in
        ''|*[!0-9]*) echo "ERROR: invalid Ansible Galaxy retry setting: $value" >&2; exit 2 ;;
    esac
done
[ "$max_attempts" -gt 0 ] || {
    echo "ERROR: ANSIBLE_GALAXY_MAX_ATTEMPTS must be greater than zero" >&2
    exit 2
}
[ "$api_timeout" -gt 0 ] || {
    echo "ERROR: ANSIBLE_GALAXY_TIMEOUT must be greater than zero" >&2
    exit 2
}

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
    echo "Ansible Galaxy collection install attempt $attempt/$max_attempts"
    if ansible-galaxy collection install --timeout "$api_timeout" \
            nvidia.nvue community.general ansible.netcommon; then
        exit 0
    fi
    if [ "$attempt" -eq "$max_attempts" ]; then
        echo "ERROR: Ansible Galaxy collection installation failed after $max_attempts attempts" >&2
        exit 1
    fi
    delay=$((retry_delay * attempt))
    echo "Ansible Galaxy request failed; retrying in ${delay}s" >&2
    [ "$delay" -eq 0 ] || sleep "$delay"
    attempt=$((attempt + 1))
done
