# Docker deployment guide

This guide covers LLDPq monitoring, persistence, DHCP/ONIE provisioning,
streaming telemetry, updates, rollback boundaries, and removal with Docker.
For native Linux installation and application features, see the
[main README](README.md).

## Quick start

No installation needed. Download the pre-built Docker image and run:

The examples use `sudo` for a typical Linux Docker Engine; omit it when the
Docker CLI already runs as your user, as is usual with Docker Desktop.

> The image runs with host-level privileges. For production, verify a
> release-published SHA-256/signature before loading the archive, or build from
> a reviewed source revision. A filename, HTTPS download, or the image's
> `lldpq:latest` tag alone does not authenticate its contents.

```bash
# Download — pick the right architecture
curl -O https://aliaydemir.com/lldpq-amd64.tar.gz   # x86_64 (Linux servers, Cumulus switches)

curl -O https://aliaydemir.com/lldpq-arm64.tar.gz   # ARM64  (Apple Silicon Mac, Ampere, RPi)

# Load image
sudo docker load < lldpq-amd64.tar.gz   # or lldpq-arm64.tar.gz

# Evaluation mode: publish only the web UI, and only on host loopback
sudo docker run -d --name lldpq \
  --privileged \
  --restart unless-stopped \
  -p 127.0.0.1:8080:80 \
  -e LLDPQ_DHCP_MODE=disabled \
  -e DHCP_AUTOSTART=false \
  lldpq:latest

# Shell into container
sudo docker exec -it -u lldpq lldpq bash
```

Open `http://127.0.0.1:8080` on the Docker host. For remote access, forward the
loopback port through the Docker host's normal SSH service, then open the same
URL locally:

```bash
ssh -L 8080:127.0.0.1:8080 admin@docker-host
```

The bridge/port-mapping command above is portable across Linux and Docker
Desktop. Docker Desktop 4.34+ also offers opt-in host networking at Layer 4,
but it still cannot provide LLDPq's physical-L2 DHCP/ONIE service. Use the
dedicated Linux provisioning mode below for that workflow. See Docker's
[host-network driver documentation](https://docs.docker.com/engine/network/drivers/host/).

> **Critical security boundary:** the image runs with `--privileged`. It also
> starts an internal SSH service whose `lldpq` user has passwordless sudo, and
> the current entrypoint resets that user's password to the known value
> `lldpq` on every start. The recommended bridge command deliberately does not
> publish TCP/2033. Do not expose port 2033 or use host networking unless a
> trusted-source firewall/ACL protects it. Prefer `docker exec` for shell
> access. The web defaults are `admin/admin` and `operator/operator`; change
> both immediately from **User Management**. Do not submit login or switch
> credentials over plaintext HTTP on an untrusted or routed network; keep the
> loopback/SSH-tunnel path or put LLDPq behind a TLS reverse proxy and a
> source-restricted firewall.

The commands above run LLDPq in **non-persistent monitoring mode** for
evaluation. Recreating that container loses configuration, SSH keys, and
results. Use a persistent deployment below before entering real inventory or
device credentials. DHCP/ONIE provisioning is disabled unless the explicit
Linux host-network mode is selected.

## Persistent deployment

### Direct `docker run`

The following bridge-network monitoring deployment survives container
recreation and does not publish the internal SSH service:

```bash
sudo docker run -d --name lldpq \
  --privileged \
  --restart unless-stopped \
  -p 127.0.0.1:8080:80 \
  -e LLDPQ_DHCP_MODE=disabled \
  -e DHCP_AUTOSTART=false \
  -v lldpq-data:/home/lldpq/lldpq/monitor-results \
  -v lldpq-lldp-data:/home/lldpq/lldpq/lldp-results \
  -v lldpq-alert-state:/home/lldpq/lldpq/alert-states \
  -v lldpq-lldp-jobs:/var/lib/lldpq/lldp-jobs \
  -v lldpq-assets-jobs:/var/lib/lldpq/assets-jobs \
  -v lldpq-upgrade-jobs:/var/lib/lldpq/upgrade-jobs \
  -v lldpq-ai-state:/var/lib/lldpq/ai \
  -v lldpq-provision-jobs:/var/lib/lldpq/provision-jobs \
  -v lldpq-provision-state:/var/lib/lldpq/provision-state \
  -v lldpq-dhcp-state:/var/lib/dhcp \
  -v lldpq-configs:/var/www/html/configs \
  -v lldpq-hstr:/var/www/html/hstr \
  -v lldpq-generated-configs:/var/www/html/generated_config_folder \
  -v lldpq-provision-files:/var/www/html/provision-uploads \
  -v lldpq-system-config:/home/lldpq/lldpq/system-config \
  -v lldpq-app-config:/home/lldpq/lldpq/config \
  -v lldpq-ssh:/home/lldpq/.ssh \
  -v lldpq-ansible:/home/lldpq/ansible \
  lldpq:latest
```

`lldpq-system-config` stores `/etc/lldpq.conf`, `dhcpd.conf`, `dhcpd.hosts`
and the ISC DHCP interface setting. The entrypoint keeps their normal `/etc`
paths as symlinks. `lldpq-app-config` stores inventory, lifecycle tracking,
topology, notification, login, ZTP, serial-mapping and display-alias settings;
`lldpq-ssh` stores switch SSH keys, and `lldpq-ansible` stores
inventory/playbooks/host and group vars.
`lldpq-lldp-data` stores the current LLDP validation result and
`lldpq-alert-state` stores notification history/deduplication state, preventing
duplicate recovery/outage notifications after a container replacement.
The LLDP/Assets/Provision job volumes retain queued and resumable work,
`lldpq-upgrade-jobs` retains multi-device upgrade progress,
`lldpq-ai-state` retains private Ask-AI memory/analysis snapshots, and
`lldpq-provision-state` retains discovery cache, DHCP desired state and
scheduler state.
`lldpq-dhcp-state` retains the DHCP lease database. Generated NVUE ZTP files
and uploaded OS images/ONIE aliases live in `lldpq-generated-configs` and
`lldpq-provision-files` respectively.
Existing direct file mounts remain supported. The web report tree is
intentionally separate from raw monitoring data and is re-seeded from the
last-known-good source data when a container is recreated.

### Docker Compose

After loading the pre-built image in [Quick start](#quick-start), obtain the
Compose file from the source checkout and start the monitoring deployment from
that checkout directory:

```bash
git clone https://github.com/aliaydemir/lldpq-src.git
cd lldpq-src
sudo env LLDPQ_PORT=127.0.0.1:8080 \
  docker compose -f docker/docker-compose.yml up -d --no-build
sudo docker compose -f docker/docker-compose.yml ps
```

This creates the same persistent named volumes shown above and keeps Compose
labels needed by the update and removal workflows. Continue using the same
checkout directory and optional Compose project name for later operations.

## First-time setup

Complete these steps through the loopback/SSH-tunnel path above, or through a
TLS reverse proxy restricted to trusted management sources:

1. Login as admin and go to **Assets**.
2. Click **Edit Devices** and add switch hostnames and management IPs (see the
   [devices.yaml format](README.md#devicesyaml-format)).
3. Click the orange **SSH Setup** button.
4. Enter the device password twice to confirm it.
5. Click **Run Setup** to generate and distribute SSH keys.
6. Retry failed devices with the appropriate password.
7. Change both default web passwords immediately from **User Management**.

The admin **Setup** page also provides the guided inventory → SSH keys →
topology → aliases → Ansible → notifications → run workflow; see
[guided web setup](README.md#03b-guided-web-setup-setup-page).

LLDPq needs only the switch hostnames and management IPs; SSH keys are
generated and distributed from the web UI. Docker deployments work on common
Linux distributions, Cumulus Linux, and Docker Desktop on macOS.

On a Cumulus Docker host, keep the loopback binding and use an SSH tunnel when
possible. If direct management-network access is required, bind the container
port to the host's specific management IP (not every interface), choose an
unused ACL rule ID, and permit only the trusted source prefix. The following
example uses documentation addresses; replace all three values and review the
entire pending NVUE diff before applying it:

```bash
rule=200
trusted_cidr=192.0.2.0/24
web_port=8080
nv set acl acl-default-whitelist rule "$rule" match ip source-ip "$trusted_cidr"
nv set acl acl-default-whitelist rule "$rule" match ip tcp dest-port "$web_port"
nv set acl acl-default-whitelist rule "$rule" action permit
nv config diff
# Run only if the diff contains no unrelated pending changes:
nv config apply -y
```

## DHCP/ONIE provisioning

The default `docker/docker-compose.yml` uses bridge networking and is intended
for monitoring. It sets `LLDPQ_DHCP_MODE=disabled`, so the Provision page
cannot start a DHCP server that would be isolated inside the container
network.

To serve DHCP/ONIE on a physical Layer-2 network, use the dedicated Compose
file on a **Linux Docker Engine** host. The selected IPv4 address must already
be assigned to the physical interface, and host port 80 must be free:

```bash
git clone https://github.com/aliaydemir/lldpq-src.git
cd lldpq-src
DHCP_INTERFACE=eno1 PROVISION_SERVER_IP=192.168.100.200 \
  docker compose -f docker/docker-compose.provisioning.yml up -d
```

The Compose files come from the source checkout; they are not contained in the
pre-built image archive itself.

This explicit mode uses host networking, validates the interface/address pair
at startup, and persists the DHCP desired state. `DHCP_AUTOSTART` defaults to
`false`; save and validate the network-specific DHCP configuration in
**Provision** before starting DHCP. Do not enable DHCP by adding only
`--network host` or `LLDPQ_DHCP_MODE=host` to an arbitrary container—the
dedicated Compose file supplies the complete guarded configuration. Docker
Desktop on macOS cannot provide this physical-L2 DHCP/ONIE mode; use it for
monitoring only.

> **Host-network warning:** provisioning mode also exposes the container's
> plaintext web service on TCP/80 and its internal SSH service on TCP/2033.
> Restrict both at the host/network boundary to the exact provisioning and
> administration source ranges required. Never expose TCP/2033 publicly, and
> use a TLS-protected management path for web administration.

## Ansible integration

Ansible, ansible-lint, and the required collections are installed in the
image, but integration is disabled by default with `ANSIBLE_DIR=NoNe`. A mount
or file copy alone does not enable the VLAN/VRF reports or Fabric tools.

For a new persistent direct deployment, keep the `lldpq-ansible` named volume
and add `ANSIBLE_DIR` to the `docker run` command:

```bash
# Add this argument to the persistent docker run command above
-e ANSIBLE_DIR=/home/lldpq/ansible
```

Copy the project into that volume, normalize container ownership, then enable
the same path from **Setup → Integrate Ansible**:

```bash
sudo docker cp ~/my_ansible_project/. lldpq:/home/lldpq/ansible/
sudo docker exec lldpq \
  chown -R lldpq:www-data /home/lldpq/ansible
```

The copied project survives recreation only when the container has the
`lldpq-ansible` named volume (or an equivalent host bind mount) from the
persistent deployment. A Quick-start container without that mount is
ephemeral.

A host bind mount is possible, but the image recursively changes ownership of
`/home/lldpq/ansible` to `lldpq:www-data` at startup. On Linux that also
changes numeric ownership in the host tree. Use only a dedicated copy whose
ownership may be changed; do not bind-mount an unrelated source worktree.

See [Ansible Integration](README.md#15-ansible-integration) for the required
project structure.

## Updating

### Compose deployments

For a **Compose deployment**, update from the same checkout directory, with
the same Compose file, environment, and optional `-p` project name used to
create it. The example below is monitoring mode; substitute
`docker/docker-compose.provisioning.yml` and export its required interface/IP
values for provisioning mode. If the deployment used `-p`, export that exact
name as `LLDPQ_COMPOSE_PROJECT_NAME` first. The manifest check below prevents
loading an archive with the wrong tag; it does not replace the release
checksum/signature verification described in [Quick start](#quick-start):

```bash
set -Eeuo pipefail
compose_file=docker/docker-compose.yml
image_archive=lldpq-amd64.tar.gz       # use lldpq-arm64.tar.gz on ARM64
stamp=$(date +%Y%m%d-%H%M%S)
rollback_image="lldpq:pre-upgrade-$stamp"
compose_env=(sudo env "TZ=${TZ:-UTC}")
if [[ $compose_file == *provisioning* ]]; then
  : "${DHCP_INTERFACE:?Export the original DHCP_INTERFACE}"
  : "${PROVISION_SERVER_IP:?Export the original PROVISION_SERVER_IP}"
  compose_env+=(
    "DHCP_INTERFACE=$DHCP_INTERFACE"
    "PROVISION_SERVER_IP=$PROVISION_SERVER_IP"
  )
else
  LLDPQ_PORT=${LLDPQ_PORT:-127.0.0.1:8080}
  compose_env+=("LLDPQ_PORT=$LLDPQ_PORT")
fi
compose=("${compose_env[@]}" docker compose -f "$compose_file")
if [[ -n ${LLDPQ_COMPOSE_PROJECT_NAME:-} ]]; then
  compose+=(-p "$LLDPQ_COMPOSE_PROJECT_NAME")
fi

wait_ready() {
  for _ in {1..30}; do
    if sudo docker exec lldpq \
         curl -fsS http://127.0.0.1/login.html >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

"${compose[@]}" config >/dev/null
test -s "$image_archive"
archive_manifest=$(tar -xOzf "$image_archive" manifest.json)
[[ $archive_manifest == *'"lldpq:latest"'* ]]
old_image_id=$(sudo docker inspect --format '{{.Image}}' lldpq)
sudo docker image tag "$old_image_id" "$rollback_image"
sudo docker load < "$image_archive"
if ! "${compose[@]}" up -d --no-build --force-recreate || \
   ! wait_ready; then
  "${compose[@]}" logs --tail 100 lldpq || true
  sudo docker image tag "$rollback_image" lldpq:latest
  "${compose[@]}" up -d --no-build --force-recreate
  wait_ready
  echo "Replacement failed; the previous image was restored." >&2
  exit 1
fi
echo "Readiness verified; rollback image retained as $rollback_image"
```

Named volumes and Compose labels remain attached; a failed readiness check
attempts to restore the previous **image**. This is not a persistent-state
rollback: startup may migrate or otherwise update shared named volumes, and
those changes are not reversed. Take a consistent external snapshot first if
the deployment requires data rollback as well.

For a post-readiness image rollback while the variables/functions from the
script above are still present, retag the printed rollback image and recreate
the same Compose service:

```bash
sudo docker image tag "$rollback_image" lldpq:latest
"${compose[@]}" up -d --no-build --force-recreate
wait_ready
```

In a later shell, set `rollback_image` to the exact retained tag and rebuild
the same `compose` array/environment from the first block. After final
acceptance, remove that tag with
`sudo docker image rm lldpq:pre-upgrade-<timestamp>`.

### Legacy or direct `docker run` migration

The longer migration below is only for a legacy or direct `docker run`
container. It captures the complete old `docker inspect` configuration, stops
the container before copying mutable state, migrates into fresh per-attempt
named volumes, and keeps the stopped old container under a rollback name until
readiness passes. Its writable layer and original volumes are retained; only
mounts deliberately reused through `extra_args` remain shared.

> Before starting, let active Assets/LLDP refreshes,
> discovery/post-provision jobs, and OS upgrades reach a terminal state. Do
> not change Setup or Provision configuration while the backup is being
> captured. If any job state is ambiguous, leave
> `LLDPQ_MIGRATION_OPTIONS_CONFIRMED` unset and inspect the old container; the
> script will only inspect the deployment and prepare backup metadata; it will
> not load the candidate image or stop/replace the running container.

```bash
# One-time migration backup + image/container rollback replacement
set -Eeuo pipefail
umask 077
container=lldpq
stamp=$(date +%Y%m%d-%H%M%S)
old_container="${container}-pre-upgrade-${stamp}"
backup="$HOME/lldpq-container-backup-$stamp"
volume_prefix="${container}-migration-${stamp}"
image_archive=lldpq-amd64.tar.gz             # use lldpq-arm64.tar.gz on ARM64
mkdir -p "$backup/app-config" "$backup/ssh" "$backup/ansible" \
  "$backup/web-root" "$backup/dhcp-state" "$backup/lldp-jobs" \
  "$backup/assets-jobs" "$backup/upgrade-jobs" "$backup/ai" \
  "$backup/provision-jobs" "$backup/provision-state"
sudo docker container inspect "$container" >/dev/null
old_image_id=$(sudo docker inspect --format '{{.Image}}' "$container")
rollback_image="lldpq:pre-migration-$stamp"
sudo docker inspect "$container" > "$backup/container-inspect.json"
sudo docker inspect --format \
  'Restart={{json .HostConfig.RestartPolicy}} Env={{json .Config.Env}} Mounts={{json .Mounts}} Network={{json .HostConfig.NetworkMode}} Ports={{json .HostConfig.PortBindings}}' \
  "$container" > "$backup/container-options.txt"

# Validate the candidate archive and its expected tag before requesting the
# outage. This prevents an unrelated archive from silently reusing the old
# lldpq:latest tag.
test -s "$image_archive"
archive_manifest=$(tar -xOzf "$image_archive" manifest.json)
[[ $archive_manifest == *'"lldpq:latest"'* ]]

copy_required() {
  src=$1 dest=$2
  # -L follows application symlinks such as /etc/lldpq.conf.
  sudo docker cp -L "$container:$src" "$dest"
  test -e "$dest"
}
copy_tree_required() {
  src=$1 dest=$2
  sudo docker cp "$container:$src" "$dest"
}
copy_optional() {
  src=$1 dest=$2
  error_file=$(mktemp)
  if sudo docker cp -L "$container:$src" "$dest" 2>"$error_file"; then
    rm -f "$error_file"
    test -e "$dest"
    return
  fi
  # docker cp works for both running and stopped containers. Only a confirmed
  # missing optional path may be skipped; daemon/storage/permission failures
  # abort the migration; the error trap restarts the previous container.
  if grep -Eqi 'no such file or directory|could not find the file' "$error_file"; then
    rm -f "$error_file"
    return 0
  fi
  cat "$error_file" >&2
  rm -f "$error_file"
  return 1
}
copy_tree_optional() {
  src=$1 dest=$2
  error_file=$(mktemp)
  if sudo docker cp "$container:$src" "$dest" 2>"$error_file"; then
    rm -f "$error_file"
    return
  fi
  if grep -Eqi 'no such file or directory|could not find the file' "$error_file"; then
    rm -f "$error_file"
    return 0
  fi
  cat "$error_file" >&2
  rm -f "$error_file"
  return 1
}

# Review the captured options before allowing the short outage. Add every
# deployment-specific -e/-v/-p/--network/--restart option to extra_args below.
# If Ansible was a host bind mount, remove the Ansible named-volume entry
# from persistent_args and put that bind mount in extra_args instead.
# The defaults below are intentionally bridge-mode monitoring and do not expose
# the image's internal SSH service.
cat "$backup/container-options.txt"
extra_args=(
  --privileged
  --restart unless-stopped
  -p 127.0.0.1:8080:80
  -e LLDPQ_DHCP_MODE=disabled
  -e DHCP_AUTOSTART=false
)
persistent_args=(
  -v "${volume_prefix}-data:/home/lldpq/lldpq/monitor-results"
  -v "${volume_prefix}-lldp-data:/home/lldpq/lldpq/lldp-results"
  -v "${volume_prefix}-alert-state:/home/lldpq/lldpq/alert-states"
  -v "${volume_prefix}-lldp-jobs:/var/lib/lldpq/lldp-jobs"
  -v "${volume_prefix}-assets-jobs:/var/lib/lldpq/assets-jobs"
  -v "${volume_prefix}-upgrade-jobs:/var/lib/lldpq/upgrade-jobs"
  -v "${volume_prefix}-ai-state:/var/lib/lldpq/ai"
  -v "${volume_prefix}-provision-jobs:/var/lib/lldpq/provision-jobs"
  -v "${volume_prefix}-provision-state:/var/lib/lldpq/provision-state"
  -v "${volume_prefix}-dhcp-state:/var/lib/dhcp"
  -v "${volume_prefix}-configs:/var/www/html/configs"
  -v "${volume_prefix}-hstr:/var/www/html/hstr"
  -v "${volume_prefix}-generated-configs:/var/www/html/generated_config_folder"
  -v "${volume_prefix}-provision-files:/var/www/html/provision-uploads"
  -v "${volume_prefix}-system-config:/home/lldpq/lldpq/system-config"
  -v "${volume_prefix}-app-config:/home/lldpq/lldpq/config"
  -v "${volume_prefix}-ssh:/home/lldpq/.ssh"
  -v "${volume_prefix}-ansible:/home/lldpq/ansible"
)
migration_volumes=()
for ((i=0; i<${#persistent_args[@]}; i+=2)); do
  volume_spec=${persistent_args[i+1]}
  migration_volumes+=("${volume_spec%%:*}")
done
if [[ ${LLDPQ_MIGRATION_OPTIONS_CONFIRMED:-false} != true ]]; then
  echo "Running container unchanged. Review $backup/container-options.txt, edit extra_args/persistent_args, export LLDPQ_MIGRATION_OPTIONS_CONFIRMED=true, then rerun." >&2
  exit 2
fi

sudo docker image tag "$old_image_id" "$rollback_image"
if ! sudo docker load < "$image_archive" || \
   ! sudo docker image inspect lldpq:latest >/dev/null; then
  sudo docker image tag "$rollback_image" lldpq:latest
  exit 1
fi

rollback_container() {
  rc=$?
  trap - ERR INT TERM
  set +e
  if [[ ${old_rename_intent:-false} == true ]] && \
     sudo docker container inspect "$old_container" >/dev/null 2>&1; then
    sudo docker rm -f "$container" >/dev/null 2>&1
    sudo docker rename "$old_container" "$container"
    sudo docker start "$container"
    echo "Replacement failed; the previous container was restarted (deliberately reused mounts were not rolled back)." >&2
  else
    # Failure before/while rename: the live container still has its original
    # name and may only need to be started again.
    sudo docker start "$container" >/dev/null 2>&1 || true
    echo "Replacement failed before the rollback rename completed; the original container was left in place." >&2
  fi
  sudo docker volume rm "${migration_volumes[@]}" >/dev/null 2>&1 || true
  sudo docker image tag "$rollback_image" lldpq:latest >/dev/null 2>&1 || true
  exit "$rc"
}

# Keep the old container intact under a rollback name.
if sudo docker container inspect "$old_container" >/dev/null 2>&1; then
  echo "Rollback name already exists: $old_container" >&2
  exit 1
fi
old_rename_intent=false
trap rollback_container ERR INT TERM
sudo docker stop "$container"

# Copy all mutable state only after the legacy container is stopped. Core
# identity is required; every other existing path must copy successfully.
copy_required /etc/lldpq.conf "$backup/lldpq.conf"
copy_optional /etc/dhcp/dhcpd.conf "$backup/dhcpd.conf"
copy_optional /etc/dhcp/dhcpd.hosts "$backup/dhcpd.hosts"
copy_optional /etc/default/isc-dhcp-server "$backup/isc-dhcp-server"
copy_optional /home/lldpq/lldpq/monitor-results "$backup/monitor-results"
copy_optional /home/lldpq/lldpq/lldp-results "$backup/lldp-results"
copy_optional /home/lldpq/lldpq/alert-states "$backup/alert-states"
copy_tree_optional /var/lib/lldpq/lldp-jobs/. "$backup/lldp-jobs/"
copy_tree_optional /var/lib/lldpq/assets-jobs/. "$backup/assets-jobs/"
copy_tree_optional /var/lib/lldpq/upgrade-jobs/. "$backup/upgrade-jobs/"
copy_tree_optional /var/lib/lldpq/ai/. "$backup/ai/"
copy_tree_optional /var/lib/lldpq/provision-jobs/. "$backup/provision-jobs/"
copy_tree_optional /var/lib/lldpq/provision-state/. "$backup/provision-state/"
copy_optional /var/www/html/configs "$backup/configs"
copy_optional /var/www/html/hstr "$backup/hstr"
copy_tree_optional /home/lldpq/.ssh/. "$backup/ssh/"
copy_tree_optional /home/lldpq/ansible/. "$backup/ansible/"
copy_tree_optional /var/lib/dhcp/. "$backup/dhcp-state/"
# Preserve root-level uploaded images/ONIE aliases and every other dynamic web
# artifact. Static application files are retained in the backup but are not
# copied over the replacement image.
copy_tree_required /var/www/html/. "$backup/web-root/"
copy_optional /home/lldpq/lldpq/devices.yaml "$backup/app-config/devices.yaml"
copy_optional /home/lldpq/lldpq/tracking.yaml "$backup/app-config/tracking.yaml"
copy_optional /home/lldpq/lldpq/notifications.yaml "$backup/app-config/notifications.yaml"
copy_optional /var/www/html/inventory.json "$backup/app-config/inventory.json"
copy_optional /var/www/html/topology.dot "$backup/app-config/topology.dot"
copy_optional /var/www/html/topology_config.yaml "$backup/app-config/topology_config.yaml"
copy_optional /etc/lldpq-users.conf "$backup/app-config/lldpq-users.conf"
copy_optional /var/www/html/cumulus-ztp.sh "$backup/app-config/cumulus-ztp.sh"
copy_optional /var/www/html/serial-mapping.txt "$backup/app-config/serial-mapping.txt"
copy_optional /var/www/html/display-aliases.json "$backup/app-config/display-aliases.json"
test -s "$backup/lldpq.conf"
printf 'backup completed for %s at %s\n' "$container" "$(date -Is)" > "$backup/COMPLETE"
test -s "$backup/COMPLETE"

old_rename_intent=true
sudo docker rename "$container" "$old_container"
sudo docker create --name "$container" \
  "${extra_args[@]}" "${persistent_args[@]}" \
  lldpq:latest

# Import the legacy data into the new named volumes while the container is stopped.
sudo docker cp "$backup/lldpq.conf" "$container":/home/lldpq/lldpq/system-config/lldpq.conf
test ! -f "$backup/dhcpd.conf" || sudo docker cp "$backup/dhcpd.conf" "$container":/home/lldpq/lldpq/system-config/dhcpd.conf
test ! -f "$backup/dhcpd.hosts" || sudo docker cp "$backup/dhcpd.hosts" "$container":/home/lldpq/lldpq/system-config/dhcpd.hosts
test ! -f "$backup/isc-dhcp-server" || sudo docker cp "$backup/isc-dhcp-server" "$container":/home/lldpq/lldpq/system-config/isc-dhcp-server
test ! -d "$backup/monitor-results" || sudo docker cp "$backup/monitor-results/." "$container":/home/lldpq/lldpq/monitor-results/
test ! -d "$backup/lldp-results" || sudo docker cp "$backup/lldp-results/." "$container":/home/lldpq/lldpq/lldp-results/
test ! -d "$backup/alert-states" || sudo docker cp "$backup/alert-states/." "$container":/home/lldpq/lldpq/alert-states/
sudo docker cp "$backup/lldp-jobs/." "$container":/var/lib/lldpq/lldp-jobs/
sudo docker cp "$backup/assets-jobs/." "$container":/var/lib/lldpq/assets-jobs/
sudo docker cp "$backup/upgrade-jobs/." "$container":/var/lib/lldpq/upgrade-jobs/
sudo docker cp "$backup/ai/." "$container":/var/lib/lldpq/ai/
sudo docker cp "$backup/provision-jobs/." "$container":/var/lib/lldpq/provision-jobs/
sudo docker cp "$backup/provision-state/." "$container":/var/lib/lldpq/provision-state/
test ! -d "$backup/configs" || sudo docker cp "$backup/configs/." "$container":/var/www/html/configs/
test ! -d "$backup/hstr" || sudo docker cp "$backup/hstr/." "$container":/var/www/html/hstr/
sudo docker cp "$backup/app-config/." "$container":/home/lldpq/lldpq/config/
sudo docker cp "$backup/ssh/." "$container":/home/lldpq/.ssh/
sudo docker cp "$backup/ansible/." "$container":/home/lldpq/ansible/
sudo docker cp "$backup/dhcp-state/." "$container":/var/lib/dhcp/
test ! -d "$backup/web-root/generated_config_folder" || sudo docker cp "$backup/web-root/generated_config_folder/." "$container":/var/www/html/generated_config_folder/
test ! -d "$backup/web-root/provision-uploads" || sudo docker cp "$backup/web-root/provision-uploads/." "$container":/var/www/html/provision-uploads/

# Legacy images lived directly in WEB_ROOT. Store them in the new provision volume.
shopt -s nullglob
for image in "$backup/web-root"/*.bin "$backup/web-root"/*.img "$backup/web-root"/*.iso; do
  [[ -L "$image" ]] && continue
  sudo docker cp "$image" "$container":/var/www/html/provision-uploads/
done
for alias in onie-installer-x86_64 onie-installer-x86_64-mlnx onie-installer; do
  if [[ -L "$backup/web-root/$alias" ]]; then
    target=$(basename "$(readlink "$backup/web-root/$alias")")
    alias_stage=$(mktemp -d)
    ln -s "$target" "$alias_stage/$alias"
    sudo docker cp "$alias_stage/$alias" "$container":/var/www/html/provision-uploads/
    rm -rf "$alias_stage"
  elif [[ -f "$backup/web-root/$alias" ]]; then
    sudo docker cp "$backup/web-root/$alias" "$container":/var/www/html/provision-uploads/
  fi
done
shopt -u nullglob

sudo docker start "$container"
ready=false
for _ in {1..30}; do
  if [[ $(sudo docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null) == true ]] && \
     sudo docker exec "$container" curl -fsS http://127.0.0.1/login.html >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [[ $ready != true ]]; then
  sudo docker logs --tail 100 "$container" >&2 || true
  false
fi

trap - ERR INT TERM
echo "Upgrade verified. Rollback container retained as: $old_container"
echo "Rollback image retained as: $rollback_image"
echo "After final acceptance, use the removal section to inspect and delete retained rollback volumes."
```

If you need an image/container rollback after the readiness check, the old
container and old image are retained. The migration uses per-attempt named
volumes, so its copied state is not shared with the old container; only bind
mounts deliberately preserved through `extra_args` remain shared. In the same
shell run:

```bash
failed_container="${container}-failed-${stamp}"
sudo docker image tag "$rollback_image" lldpq:latest
sudo docker stop lldpq
sudo docker rename lldpq "$failed_container"
sudo docker rename "$old_container" lldpq
sudo docker start lldpq
```

The failed candidate is kept under the printed `lldpq-failed-*` name so its
per-attempt volumes remain inspectable and removable.

## Streaming telemetry

The optional OTEL Collector, Prometheus, and Alertmanager stack runs as a
separate Compose project on the Docker host. Do not delete or recreate LLDPq
merely to enable telemetry.

With bridge networking or Docker Desktop, `127.0.0.1` inside LLDPq is not the
Docker host. Set `PROMETHEUS_URL` to an address reachable from the LLDPq
container and manage the telemetry stack from the host. Linux host-network
deployments can use `http://127.0.0.1:9090`.

The telemetry assets are in the source repository; they are not embedded in
the pre-built LLDPq image. Copy and start the stack without overwriting an
existing deployment. Set `LLDPQ_SOURCE_DIR` first if an existing checkout is
somewhere other than `$HOME/lldpq-src`. For production, point it at a reviewed
revision; the fallback clone obtains the current default branch and must be
reviewed before use:

```bash
set -Eeuo pipefail
umask 077
source_dir=${LLDPQ_SOURCE_DIR:-"$HOME/lldpq-src"}
telemetry_dir="$HOME/lldpq-telemetry"
if [[ ! -f "$source_dir/telemetry/docker-compose.yaml" ]]; then
  if [[ -e "$source_dir" ]]; then
    echo "Source directory exists but has no telemetry stack: $source_dir" >&2
    exit 1
  fi
  git clone --depth 1 https://github.com/aliaydemir/lldpq-src.git "$source_dir"
fi
if [[ -e "$telemetry_dir" ]]; then
  echo "Refusing to overwrite existing telemetry directory: $telemetry_dir" >&2
  exit 1
fi
cp -R "$source_dir/telemetry" "$telemetry_dir"
```

Harden the copied `docker-compose.yaml` before starting it. The repository
defaults publish OTLP (4317/4318), the collector exporter (8889), Prometheus
(9090), and Alertmanager (9093) on every host interface without application
authentication; Prometheus also enables its lifecycle and admin APIs.

- Pin the three `latest` images to reviewed versions or digests.
- Remove the host mapping for 8889; Prometheus reaches it on the internal
  Compose network.
- Publish only the OTLP receiver actually used, bind it to a specific
  management address, and firewall it to the switch source prefixes.
- Remove the Alertmanager host mapping unless administrators need it. Bind any
  required UI/API port to loopback or a protected management address.
- Remove Prometheus's `--web.enable-admin-api` unless explicitly required.
  Bind 9090 to loopback for host-network LLDPq, or to a protected host address
  reachable only by the LLDPq bridge network and trusted administrators.

Do not start the stack until those bindings and firewall rules are in place:

```bash
nano "$HOME/lldpq-telemetry/docker-compose.yaml"
sudo docker compose -f "$HOME/lldpq-telemetry/docker-compose.yaml" config
sudo docker compose -f "$HOME/lldpq-telemetry/docker-compose.yaml" up -d
```

Open the persistent configuration under LLDPq's configuration lock:

```bash
sudo docker exec -it lldpq \
  /usr/bin/flock -x /etc/lldpq.conf.lock \
  nano /etc/lldpq.conf
```

`/etc/lldpq.conf` survives container recreation only when the
`lldpq-system-config` volume from the persistent deployment is attached.

Update each key once; do not create duplicate entries:

```bash
TELEMETRY_ENABLED=true
PROMETHEUS_URL=http://127.0.0.1:9090
```

For a bridge deployment, replace the example URL with the reachable host
endpoint. Then configure selected switches from **Telemetry → Configuration →
Enable Telemetry**.

Useful checks:

```bash
sudo docker compose -f "$HOME/lldpq-telemetry/docker-compose.yaml" ps
sudo docker exec lldpq cat /etc/lldpq.conf
sudo docker logs lldpq
```

To disable safely, first use **Telemetry → Configuration → Disable Telemetry**
for the selected switches. Set the single `TELEMETRY_ENABLED` entry to `false`
under the same lock, then stop the host stack while preserving metrics:

```bash
sudo docker compose -f "$HOME/lldpq-telemetry/docker-compose.yaml" stop
```

Only when metrics history should be permanently deleted, run:

```bash
sudo docker compose \
  -f "$HOME/lldpq-telemetry/docker-compose.yaml" \
  down -v
```

## Removing LLDPq completely

This deletes LLDPq's Docker-managed configuration, monitoring history, private
AI state, uploaded images, SSH keys, and resumable job state. Inspect and
retain any backup you need before continuing. Host bind-mount source paths,
source checkouts, downloaded archives, and backup directories are outside
Docker's ownership and must be reviewed separately.

If the separate Docker telemetry stack was installed, remove it explicitly
before LLDPq. The `-v` option permanently deletes Prometheus/Alertmanager
history:

```bash
sudo docker compose \
  -f "$HOME/lldpq-telemetry/docker-compose.yaml" \
  down -v
```

Inspect `$HOME/lldpq-telemetry` afterwards and remove that host directory only
if its configuration is no longer needed.

For a Compose deployment, run `down` with the same Compose file, project
directory, and optional `-p` project name used during installation:

```bash
project_args=()
if [[ -n ${LLDPQ_COMPOSE_PROJECT_NAME:-} ]]; then
  project_args=(-p "$LLDPQ_COMPOSE_PROJECT_NAME")
fi

# Monitoring Compose deployment
sudo docker compose -f docker/docker-compose.yml \
  "${project_args[@]}" down -v --remove-orphans

# OR: provisioning Compose deployment
sudo env DHCP_INTERFACE=eno1 PROVISION_SERVER_IP=192.168.100.200 \
  docker compose -f docker/docker-compose.provisioning.yml \
  "${project_args[@]}" down -v --remove-orphans
```

Use only the command matching the deployment. For provisioning, replace the
interface and address with the original deployment values; Compose requires
them even while parsing `down`. `down -v` is important because Compose volume
names may have a project-name prefix.

For a direct `docker run` deployment:

```bash
set -Eeuo pipefail
containers=()
if sudo docker container inspect lldpq >/dev/null 2>&1; then
  containers+=(lldpq)
fi
while IFS= read -r name; do
  [[ $name == lldpq-pre-upgrade-* ]] && containers+=("$name")
done < <(sudo docker ps -a --filter 'name=lldpq-pre-upgrade-' --format '{{.Names}}')
while IFS= read -r name; do
  [[ $name == lldpq-failed-* ]] && containers+=("$name")
done < <(sudo docker ps -a --filter 'name=lldpq-failed-' --format '{{.Names}}')

volume_list=$(mktemp)
bind_list=$(mktemp)
trap 'rm -f "$volume_list" "$bind_list"' EXIT
for name in "${containers[@]}"; do
  sudo docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' \
    "$name" >> "$volume_list"
  sudo docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "bind"}}{{println .Source}}{{end}}{{end}}' \
    "$name" >> "$bind_list"
done
sort -u "$volume_list" -o "$volume_list"
sort -u "$bind_list" -o "$bind_list"

if [[ -s "$bind_list" ]]; then
  echo 'Host bind-mount paths are NOT deleted automatically:' >&2
  sed 's/^/  /' "$bind_list" >&2
fi
if ((${#containers[@]})); then
  sudo docker rm -f "${containers[@]}"
fi
while IFS= read -r volume; do
  [[ -n $volume ]] && sudo docker volume rm "$volume"
done < "$volume_list"
```

The direct-run script discovers the actual named volumes rather than assuming
stock names, including volumes created by a migration. It only reports bind
mounts; back up and remove those host paths manually if they are dedicated to
LLDPq.

After either Compose or direct-run removal, inspect and remove the exact LLDPq
image tags that are no longer needed:

```bash
sudo docker image ls --format '{{.Repository}}:{{.Tag}}' \
  | grep -E '^lldpq:(latest|pre-(upgrade|migration)-)'
sudo docker image rm lldpq:latest
# Also remove each exact retained tag printed above, for example:
# sudo docker image rm lldpq:pre-upgrade-20260708-120000
```

Downloaded archives, source/telemetry directories, and backup bundles are not
deleted automatically. Review them individually.

## File transfer and shell access

The recommended bridge deployment publishes only the web UI, on host loopback
port 8080 by default. Use `docker cp` and `docker exec` instead of exposing the
image's known-password SSH service.

```bash
# docker cp (from the host machine)
sudo docker cp myfile.yaml lldpq:/home/lldpq/ansible/inventory/host_vars/

# interactive shell as the service user
sudo docker exec -it -u lldpq lldpq bash

# root shell for container administration
sudo docker exec -it lldpq bash
```

For remote administration, first connect to the Docker host through its normal
hardened SSH service, then run these Docker commands locally on that host.

## Useful Docker commands

```bash
sudo docker logs lldpq                        # Container logs
sudo docker exec -it -u lldpq lldpq bash      # Shell as lldpq user
sudo docker exec -it lldpq bash               # Shell as root
sudo docker restart lldpq                     # Restart (keeps data + SSH keys)
sudo docker ps -a --filter name=lldpq          # Container status
```

### Built-in tools

Available inside the container shell:
`exa`, `nano`, `tmux`, `colordiff`, `dos2unix`, `bash-completion`, `net-tools`, `bzip2`, `jq`, `git`, `curl`, `tcpdump`, `ansible`, `ansible-lint`, `ansible-galaxy`
