#!/usr/bin/env bash
# LLDPq Uninstaller — removes everything install.sh sets up
#
# Usage:
#   ./uninstall.sh            # interactive (requires exact UNINSTALL confirmation)
#   ./uninstall.sh -y|--yes   # non-interactive
#   ./uninstall.sh --dry-run  # show what would be removed, do nothing
#   ./uninstall.sh --keep-data  # retain six Setup configs + selected runtime/history
#   ./uninstall.sh --force-partial # also remove an unrecognized partial install tree
#   ./uninstall.sh --remove-source # also remove the provenance-bound LLDPQ_SRC checkout
#   ./uninstall.sh --remove-nginx  # also remove nginx + fcgiwrap packages
#   ./uninstall.sh --remove-docker # also remove Docker packages and data
#   ./uninstall.sh --remove-dhcp   # also remove isc-dhcp-server package/config
#   ./uninstall.sh --yes --remove-source --remove-nginx --remove-dhcp --remove-docker
#                              # full LLDPq + explicitly selected host packages/data
#
# What it removes:
#   - LLDPq cron entries (/etc/crontab + /etc/cron.d/lldpq)
#   - lldpq-trigger daemon process
#   - Console PTY bridge systemd service
#   - retained-import recovery systemd service + path watcher
#   - root-owned backup/import helper and validated native recovery remnants
#   - /usr/local/bin/{lldpq, lldpq-config, lldpq-trigger, lldpq-ai-analyze, zzh, pping, send-cmd, get-conf}
#   - /var/www/html web content (nginx + fcgiwrap site removed)
#   - $LLDPQ_INSTALL_DIR (default ~/lldpq)
#   - /etc/lldpq.conf, /etc/lldpq.conf.lock, /etc/lldpq-users.conf
#   - /var/lib/lldpq, /var/log/lldpq and the service user's ~/.lldpq-state
#   - fixed LLDPq/Ansible CGI /tmp state, locks and console-audit fallback log
#   - /etc/lldpq-source.json after a complete recognized uninstall
#     (and, with --remove-source, its bound LLDPQ_SRC)
#   - /etc/sudoers.d/{www-data-lldpq, www-data-provision}
#   - /etc/nginx/sites-{available,enabled}/lldpq + reload nginx
#   - LLDPq DHCP config markers (does NOT touch dhcp service itself unless --remove-dhcp)
#   - Telemetry docker stack + volumes (always)
#   - User www-data from $LLDPQ_USER group (best effort)

set -u
set -o pipefail

LLDPQ_BACKUP_IMPORT_HELPER="/usr/local/libexec/lldpq-backup-import.py"
LLDPQ_UPDATE_RECOVERY_HELPER="/usr/local/libexec/lldpq-update-recovery.py"
LLDPQ_UNINSTALL_HELPER="/usr/local/libexec/lldpq-uninstall.sh"
LLDPQ_UNINSTALL_GATEWAY="/usr/local/libexec/lldpq-uninstall-web.py"
LLDPQ_UNINSTALL_SUDOERS="/etc/sudoers.d/www-data-lldpq-uninstall"
LLDPQ_UNINSTALL_RUN_DIR="/run/lldpq-uninstall"
LLDPQ_LIFECYCLE_LOCK="/etc/lldpq.lifecycle.lock"
LLDPQ_UNINSTALL_ACTIVE_MARKER="/run/lldpq-uninstall.active"
LLDPQ_SOURCE_PROVENANCE="/etc/lldpq-source.json"
LLDPQ_UNINSTALL_JOB_ID="${LLDPQ_UNINSTALL_JOB_ID:-}"
LLDPQ_UPDATE_RECOVERY_SERVICE="/etc/systemd/system/lldpq-update-recovery.service"
LLDPQ_UPDATE_RECOVERY_STATE="/var/lib/lldpq/update-rollback"
LLDPQ_UPDATE_RECOVERY_MARKER="$LLDPQ_UPDATE_RECOVERY_STATE/active.json"
UNINSTALL_UPDATE_LOCK_FD=""
UNINSTALL_CONFIG_COLLECTION_LOCK_FD=""
UNINSTALL_UPDATE_LOCK_PATH=""

if [[ -n "$LLDPQ_UNINSTALL_JOB_ID" && \
      ! "$LLDPQ_UNINSTALL_JOB_ID" =~ ^[a-f0-9]{32}$ ]]; then
    echo "Refusing invalid LLDPQ_UNINSTALL_JOB_ID" >&2
    exit 1
fi

load_lldpq_uninstall_config() {
    local config_file="${1:-/etc/lldpq.conf}"
    local line key raw value

    [[ -f "$config_file" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        case "$key" in
            LLDPQ_DIR|LLDPQ_USER|LLDPQ_SRC|WEB_ROOT|ANSIBLE_DIR|EDITOR_ROOT|PROJECT_DIR) ;;
            *) continue ;;
        esac
        raw="${BASH_REMATCH[2]}"
        value="$raw"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [[ ${#value} -ge 2 ]]; then
            if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || \
               [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
                value="${value:1:${#value}-2}"
            fi
        fi
        printf -v "$key" '%s' "$value"
    done < "$config_file"
}

canonical_path() {
    local path="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath -m -- "$path"
    else
        python3 -c 'import os,sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' "$path"
    fi
}

guard_destructive_path() {
    local label="$1" path="$2" min_depth="${3:-2}"
    local canonical relative depth

    # uninstall.sh still has a legacy command runner for fixed administrative
    # commands, so managed path values use a deliberately narrow character set.
    if [[ -z "$path" || ! "$path" =~ ^/[A-Za-z0-9._/+:-]+$ ]]; then
        echo "Refusing unsafe $label path: '$path'" >&2
        return 1
    fi
    canonical=$(canonical_path "$path") || return 1
    case "$canonical" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var|/var/www|"$HOME")
            echo "Refusing unsafe $label path: '$canonical'" >&2
            return 1
            ;;
    esac
    relative="${canonical#/}"
    depth=$(awk -F/ '{print NF}' <<< "$relative")
    if (( depth < min_depth )); then
        echo "Refusing shallow $label path: '$canonical'" >&2
        return 1
    fi
    printf '%s\n' "$canonical"
}

guard_recursive_target() {
    local label="$1" canonical="$2" allow_var_www="${3:-false}"
    local canonical_home
    canonical_home=$(canonical_path "$HOME") || return 1
    case "$canonical" in
        /home/*|/root/*)
            if [[ "$canonical" != "$canonical_home"/* ]]; then
                echo "Refusing $label under another user's home: '$canonical'" >&2
                return 1
            fi
            ;;
    esac
    if [[ "$allow_var_www" == "true" && "$canonical" == /var/www/* ]]; then
        printf '%s\n' "$canonical"
        return 0
    fi
    case "$canonical" in
        /bin/*|/boot/*|/dev/*|/etc/*|/lib/*|/lib64/*|/proc/*|/run/*|/sbin/*|/sys/*|/usr/*|/var/*)
            echo "Refusing $label inside protected system tree: '$canonical'" >&2
            return 1
            ;;
    esac
    printf '%s\n' "$canonical"
}

paths_overlap() {
    local first="${1%/}" second="${2%/}"
    [[ "$first" == "$second" || "$first" == "$second"/* || "$second" == "$first"/* ]]
}

guard_preserved_source_from_cleanup() {
    local source_path="$1" install_dir="$2" web_root="$3" state_dir="$4"
    local canonical_source canonical_state index
    local -a labels=(
        "LLDPQ_DIR" "WEB_ROOT" "service .lldpq-state"
        "private /var/lib/lldpq state" "dedicated /var/log/lldpq logs"
    )
    local -a targets=(
        "$install_dir" "$web_root" "$state_dir"
        "/var/lib/lldpq" "/var/log/lldpq"
    )

    [[ -n "$source_path" ]] || return 0
    if [[ "$source_path" != /* || "$source_path" == *$'\n'* || \
          "$source_path" == *$'\r'* ]]; then
        echo "Refusing uninstall: configured LLDPQ_SRC is not one safe absolute path: '$source_path'" >&2
        return 1
    fi
    canonical_source=$(canonical_path "$source_path") || {
        echo "Refusing uninstall: configured LLDPQ_SRC could not be canonicalized" >&2
        return 1
    }
    if [[ "$source_path" != "$canonical_source" ]]; then
        echo "Refusing uninstall: configured LLDPQ_SRC is not canonical: '$source_path'" >&2
        echo "Repair LLDPQ_SRC to its canonical checkout path before retrying." >&2
        return 1
    fi
    canonical_state=$(canonical_path "$state_dir") || {
        echo "Refusing uninstall: service .lldpq-state path could not be canonicalized" >&2
        return 1
    }
    targets[2]="$canonical_state"
    if $REMOVE_DOCKER_PKG; then
        labels+=("requested Docker engine data" "requested containerd data")
        targets+=("/var/lib/docker" "/var/lib/containerd")
    fi

    for ((index = 0; index < ${#targets[@]}; index++)); do
        if paths_overlap "$canonical_source" "${targets[$index]}"; then
            echo "Refusing uninstall: LLDPQ_SRC overlaps ${labels[$index]}: $canonical_source" >&2
            echo "Move the source checkout outside managed LLDPq trees (or repair LLDPQ_SRC) before retrying." >&2
            return 1
        fi
    done
    printf '%s\n' "$canonical_source"
}

source_provenance_operation() {
    local action="$1" source_path="$2" user="$3" user_home="$4"
    local install_dir="$5" web_root="$6" ansible_dir="$7" editor_root="$8"
    local project_dir="$9"

    [[ "$action" == "validate" || "$action" == "remove" ]] || return 1
    sudo python3 - "$action" "$LLDPQ_SOURCE_PROVENANCE" "$source_path" \
        "$user" "$user_home" "$install_dir" "$web_root" "$ansible_dir" \
        "$editor_root" "$project_dir" <<'PYTHON_SOURCE_PROVENANCE'
import json
import os
import pwd
import stat
import sys


class SourceSafetyError(RuntimeError):
    pass


def fail(message):
    raise SourceSafetyError(message)


def duplicate_safe_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("source provenance contains a duplicate JSON key")
        value[key] = item
    return value


def read_manifest(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail("source provenance is missing or cannot be opened safely")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 65536
        ):
            fail("source provenance must be root:root 0600, regular, bounded and single-linked")
        chunks = []
        remaining = metadata.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            fail("source provenance changed while it was read")
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=duplicate_safe_object
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail("source provenance is not valid UTF-8 JSON")
    if not isinstance(payload, dict):
        fail("source provenance must be a JSON object")
    required = {
        "version", "path", "device", "inode", "uid",
        "git_device", "git_inode",
    }
    if not required.issubset(payload):
        fail("source provenance is missing a required field")
    if type(payload["version"]) is not int or payload["version"] != 1:
        fail("source provenance version is unsupported")
    if type(payload["path"]) is not str:
        fail("source provenance path has an invalid type")
    for key in required - {"path"}:
        if type(payload[key]) is not int:
            fail("source provenance field has an invalid type: " + key)
    if any(payload[key] < 0 for key in required - {"path", "version"}):
        fail("source provenance contains a negative identity")
    if payload["device"] <= 0 or payload["inode"] <= 0:
        fail("source provenance directory identity is invalid")
    if (payload["git_device"] == 0) != (payload["git_inode"] == 0):
        fail("source provenance Git identity is incomplete")
    return payload


def mount_points():
    def decode(value):
        for encoded, decoded in (
            ("\\040", " "), ("\\011", "\t"),
            ("\\012", "\n"), ("\\134", "\\"),
        ):
            value = value.replace(encoded, decoded)
        return os.path.normpath(value)

    points = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split(" - ", 1)[0].split()
                if len(fields) >= 5:
                    points.append(decode(fields[4]))
    except (OSError, UnicodeError) as exc:
        fail("mount topology could not be inspected safely")
    return points


def overlaps(first, second):
    first = first.rstrip("/") or "/"
    second = second.rstrip("/") or "/"
    return (
        first == second
        or first.startswith(second + "/")
        or second.startswith(first + "/")
    )


def regular_sentinel(root, relative, expected_device, expected_uid):
    candidate = os.path.join(root, relative)
    try:
        metadata = os.lstat(candidate)
    except OSError:
        fail("LLDPq source sentinel is missing: " + relative)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_dev != expected_device
        or metadata.st_uid != expected_uid
    ):
        fail("LLDPq source sentinel is unsafe: " + relative)


def directory_sentinel(root, relative, expected_device, expected_uid):
    candidate = os.path.join(root, relative)
    try:
        metadata = os.lstat(candidate)
    except OSError:
        fail("LLDPq source sentinel is missing: " + relative)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_dev != expected_device
        or metadata.st_uid != expected_uid
    ):
        fail("LLDPq source sentinel is unsafe: " + relative)


def validate_context(manifest, configured_source, user, declared_home,
                     protected_paths):
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        fail("configured LLDPq service account does not exist")
    if account.pw_dir != declared_home:
        fail("configured LLDPq service-account home changed during uninstall")
    home = os.path.normpath(declared_home)
    if (
        not os.path.isabs(home)
        or home == "/"
        or os.path.realpath(home) != home
        or "\x00" in home
    ):
        fail("configured LLDPq service-account home is unsafe")
    try:
        home_metadata = os.lstat(home)
    except OSError:
        fail("configured LLDPq service-account home is unavailable")
    if not stat.S_ISDIR(home_metadata.st_mode) or home_metadata.st_uid != account.pw_uid:
        fail("configured LLDPq service-account home failed its ownership check")

    source = manifest["path"]
    if (
        not source
        or len(source.encode("utf-8")) > 4096
        or not os.path.isabs(source)
        or source != os.path.normpath(source)
        or os.path.realpath(source) != source
        or any(character in source for character in "\x00\r\n")
    ):
        fail("provenance source path is not one canonical absolute directory")
    if configured_source != source:
        fail("LLDPQ_SRC no longer exactly matches its root-owned provenance")
    try:
        if os.path.commonpath((home, source)) != home or source == home:
            fail("LLDPQ_SRC must be a strict descendant of the service-account home")
    except ValueError:
        fail("LLDPQ_SRC is outside the service-account home")

    # Source checkout removal must never consume the dedicated lifecycle state,
    # SSH identity, or installer-created top-level backups.  The lexical first-
    # component rule protects a source nested below a temporarily unavailable
    # backup path; the safe home listing additionally catches an existing backup
    # symlink whose resolved target overlaps the source checkout.
    for label, candidate in (
        ("service lifecycle state", os.path.join(home, ".lldpq-state")),
        ("service SSH directory", os.path.join(home, ".ssh")),
    ):
        candidate = os.path.realpath(candidate)
        if overlaps(source, candidate):
            fail("LLDPQ_SRC overlaps protected " + label + ": " + candidate)
    relative_source = os.path.relpath(source, home)
    first_component = relative_source.split(os.sep, 1)[0]
    if first_component.startswith("lldpq-backup-"):
        fail("LLDPQ_SRC is inside a protected top-level LLDPq backup")
    try:
        home_entries = os.listdir(home)
    except OSError:
        fail("service-account home could not be listed for backup protection")
    for name in home_entries:
        if not name.startswith("lldpq-backup-"):
            continue
        backup = os.path.realpath(os.path.join(home, name))
        if overlaps(source, backup):
            fail("LLDPQ_SRC overlaps protected LLDPq backup: " + backup)

    for label, raw_path in protected_paths:
        if raw_path in ("", "NoNe"):
            continue
        if not os.path.isabs(raw_path) or any(
            character in raw_path for character in "\x00\r\n"
        ):
            fail("configured " + label + " path is unsafe")
        candidate = os.path.realpath(os.path.normpath(raw_path))
        if overlaps(source, candidate):
            fail("LLDPQ_SRC overlaps configured " + label + ": " + candidate)

    for point in mount_points():
        if point == source or point.startswith(source + "/"):
            fail("LLDPQ_SRC contains or is a mount point: " + point)

    is_git = manifest["git_device"] != 0
    try:
        source_metadata = os.lstat(source)
    except FileNotFoundError:
        # A previous invocation may have committed the guarded source-tree
        # removal and then lost power before retiring the fixed authorities.
        # Absence is safe and idempotent: there is no pathname left to follow or
        # delete, while the root-owned manifest still proves which exact path was
        # selected.  A dangling symlink is not "absent" (lstat succeeds below).
        return account, source, None, is_git, True
    except OSError:
        fail("provenance-bound LLDPQ_SRC cannot be inspected safely")
    if (
        not stat.S_ISDIR(source_metadata.st_mode)
        or source_metadata.st_dev != manifest["device"]
        or source_metadata.st_ino != manifest["inode"]
        or source_metadata.st_uid != manifest["uid"]
        or source_metadata.st_uid != account.pw_uid
    ):
        fail("LLDPQ_SRC identity no longer matches root-owned provenance")

    for relative in ("lldpq", "html", "bin", "etc"):
        directory_sentinel(
            source, relative, source_metadata.st_dev, source_metadata.st_uid
        )
    for relative in (
        "install.sh", "uninstall.sh", "README.md", "VERSION",
        "lldpq/monitor.sh", "html/setup.html", "bin/lldpq-config",
    ):
        regular_sentinel(
            source, relative, source_metadata.st_dev, source_metadata.st_uid
        )

    git_path = os.path.join(source, ".git")
    if is_git:
        try:
            git_metadata = os.lstat(git_path)
        except OSError:
            fail("provenance-bound .git directory is unavailable")
        if (
            not stat.S_ISDIR(git_metadata.st_mode)
            or git_metadata.st_dev != manifest["git_device"]
            or git_metadata.st_ino != manifest["git_inode"]
            or git_metadata.st_uid != account.pw_uid
            or git_metadata.st_dev != source_metadata.st_dev
        ):
            fail(".git identity no longer matches root-owned provenance")
        regular_sentinel(
            git_path, "HEAD", git_metadata.st_dev, account.pw_uid
        )
        directory_sentinel(
            git_path, "objects", git_metadata.st_dev, account.pw_uid
        )
        worktrees = os.path.join(git_path, "worktrees")
        if os.path.lexists(worktrees):
            worktree_metadata = os.lstat(worktrees)
            if not stat.S_ISDIR(worktree_metadata.st_mode):
                fail(".git/worktrees is not a real directory")
            try:
                if os.listdir(worktrees):
                    fail("linked Git worktrees are registered; remove them before deleting LLDPQ_SRC")
            except OSError:
                fail("linked Git worktree metadata could not be inspected")
    elif os.path.lexists(git_path):
        fail("non-Git source provenance no longer matches LLDPQ_SRC")

    return account, source, source_metadata, is_git, False


def open_directory(name, *, dir_fd=None):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=dir_fd)


def verify_opened(metadata, descriptor_metadata):
    return (
        stat.S_ISDIR(metadata.st_mode)
        and stat.S_ISDIR(descriptor_metadata.st_mode)
        and (metadata.st_dev, metadata.st_ino)
        == (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
    )


def validate_tree(directory_fd, expected_device, expected_uid, budget):
    for name in os.listdir(directory_fd):
        if name in (".", "..") or "/" in name or "\x00" in name:
            fail("LLDPQ_SRC contains an invalid directory entry")
        budget[0] += 1
        if budget[0] > 2_000_000:
            fail("LLDPQ_SRC contains too many entries for bounded removal")
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if metadata.st_dev != expected_device or metadata.st_uid != expected_uid:
            fail("LLDPQ_SRC contains a cross-device or foreign-owned entry: " + name)
        if stat.S_ISDIR(metadata.st_mode):
            try:
                child_fd = open_directory(name, dir_fd=directory_fd)
            except OSError:
                fail("LLDPQ_SRC directory changed during validation: " + name)
            try:
                opened = os.fstat(child_fd)
                if not verify_opened(metadata, opened):
                    fail("LLDPQ_SRC directory identity changed during validation: " + name)
                validate_tree(child_fd, expected_device, expected_uid, budget)
            finally:
                os.close(child_fd)
        elif not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            fail("LLDPQ_SRC contains an unsupported special file: " + name)


def remove_tree(directory_fd, expected_device, expected_uid, budget):
    while True:
        names = os.listdir(directory_fd)
        if not names:
            break
        for name in names:
            if name in (".", "..") or "/" in name or "\x00" in name:
                fail("LLDPQ_SRC contains an invalid directory entry")
            budget[0] += 1
            if budget[0] > 2_000_000:
                fail("LLDPQ_SRC contains too many entries for bounded removal")
            try:
                metadata = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                continue
            if metadata.st_dev != expected_device or metadata.st_uid != expected_uid:
                fail("LLDPQ_SRC contains a cross-device or foreign-owned entry: " + name)
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_fd = open_directory(name, dir_fd=directory_fd)
                except OSError:
                    fail("LLDPQ_SRC directory changed while it was opened: " + name)
                try:
                    opened = os.fstat(child_fd)
                    if not verify_opened(metadata, opened):
                        fail("LLDPQ_SRC directory identity changed: " + name)
                    remove_tree(child_fd, expected_device, expected_uid, budget)
                finally:
                    os.close(child_fd)
                current = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    fail("LLDPQ_SRC directory was replaced during removal: " + name)
                os.rmdir(name, dir_fd=directory_fd)
            elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                current = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                    fail("LLDPQ_SRC entry was replaced during removal: " + name)
                os.unlink(name, dir_fd=directory_fd)
            else:
                fail("LLDPQ_SRC contains an unsupported special file: " + name)
    os.fsync(directory_fd)


def open_source_for_guarded_walk(account, source, source_metadata):
    home_fd = open_directory(account.pw_dir)
    descriptors = [home_fd]
    try:
        home_metadata = os.fstat(home_fd)
        if not stat.S_ISDIR(home_metadata.st_mode) or home_metadata.st_uid != account.pw_uid:
            fail("service-account home changed while opening LLDPQ_SRC")
        relative = os.path.relpath(source, account.pw_dir)
        parts = relative.split(os.sep)
        if not parts or any(part in ("", ".", "..") for part in parts):
            fail("LLDPQ_SRC is not a safe child of the service-account home")
        current_fd = home_fd
        parent_fd = None
        source_fd = None
        for index, part in enumerate(parts):
            try:
                metadata = os.stat(
                    part, dir_fd=current_fd, follow_symlinks=False
                )
                child_fd = open_directory(part, dir_fd=current_fd)
            except OSError:
                fail("LLDPQ_SRC path changed while it was opened")
            opened = os.fstat(child_fd)
            if not verify_opened(metadata, opened):
                os.close(child_fd)
                fail("LLDPQ_SRC path identity changed while it was opened")
            if metadata.st_uid != account.pw_uid:
                os.close(child_fd)
                fail("LLDPQ_SRC path contains a foreign-owned directory")
            if index < len(parts) - 1 and stat.S_IMODE(metadata.st_mode) & 0o022:
                os.close(child_fd)
                fail("LLDPQ_SRC parent directory is group/world writable")
            descriptors.append(child_fd)
            parent_fd = current_fd
            current_fd = child_fd
            source_fd = child_fd
        opened_source = os.fstat(source_fd)
        if (opened_source.st_dev, opened_source.st_ino, opened_source.st_uid) != (
            source_metadata.st_dev, source_metadata.st_ino, source_metadata.st_uid
        ):
            fail("LLDPQ_SRC root changed during guarded inspection")
        return descriptors, parent_fd, source_fd, parts
    except Exception:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def close_descriptors(descriptors):
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def validate_source(account, source, source_metadata):
    descriptors, _parent_fd, source_fd, _parts = open_source_for_guarded_walk(
        account, source, source_metadata
    )
    try:
        validate_tree(source_fd, source_metadata.st_dev, source_metadata.st_uid, [0])
    finally:
        close_descriptors(descriptors)


def remove_source(account, source, source_metadata):
    descriptors, parent_fd, source_fd, parts = open_source_for_guarded_walk(
        account, source, source_metadata
    )
    try:
        validate_tree(source_fd, source_metadata.st_dev, source_metadata.st_uid, [0])
        remove_tree(source_fd, source_metadata.st_dev, source_metadata.st_uid, [0])
        os.close(source_fd)
        descriptors.remove(source_fd)
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
            source_metadata.st_dev, source_metadata.st_ino
        ):
            fail("LLDPQ_SRC root was replaced before final removal")
        os.rmdir(parts[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        close_descriptors(descriptors)
    if os.path.lexists(source):
        fail("LLDPQ_SRC still exists after guarded removal")


try:
    (
        action, manifest_path, configured_source, user, declared_home,
        install_dir, web_root, ansible_dir, editor_root, project_dir,
    ) = sys.argv[1:]
    if action not in ("validate", "remove"):
        fail("unsupported source provenance operation")
    manifest = read_manifest(manifest_path)
    account, source, source_metadata, is_git, source_absent = validate_context(
        manifest,
        configured_source,
        user,
        declared_home,
        (
            ("LLDPQ_DIR", install_dir),
            ("WEB_ROOT", web_root),
            ("ANSIBLE_DIR", ansible_dir),
            ("EDITOR_ROOT", editor_root),
            ("PROJECT_DIR", project_dir),
        ),
    )
    if source_absent:
        print(("git" if is_git else "non-git") + "-absent")
    elif action == "validate":
        validate_source(account, source, source_metadata)
        print("git" if is_git else "non-git")
    else:
        remove_source(account, source, source_metadata)
        print("git" if is_git else "non-git")
except SourceSafetyError as exc:
    print("Refusing LLDPQ_SRC removal: " + str(exc), file=sys.stderr)
    raise SystemExit(1)
except Exception as exc:
    print("Refusing LLDPQ_SRC removal: unexpected safety-check failure: " + str(exc), file=sys.stderr)
    raise SystemExit(1)
PYTHON_SOURCE_PROVENANCE
}

inspect_source_git_state() {
    local source_path="$1" user="$2" source_kind="$3"
    local git_bin top git_dir counts
    SOURCE_GIT_TRACKED_CHANGES=0
    SOURCE_GIT_UNTRACKED=0

    case "$source_kind" in
        git) ;;
        non-git|git-absent|non-git-absent) return 0 ;;
        *)
            echo "Refusing LLDPQ_SRC removal: unsupported source kind" >&2
            return 1
            ;;
    esac
    git_bin=$(command -v git 2>/dev/null || true)
    [[ -n "$git_bin" && "$git_bin" == /* ]] || {
        echo "Refusing LLDPQ_SRC removal: git is required to inspect this source checkout" >&2
        return 1
    }
    top=$(sudo -H -u "$user" env GIT_OPTIONAL_LOCKS=0 LC_ALL=C \
        "$git_bin" -C "$source_path" rev-parse --show-toplevel 2>/dev/null) || {
        echo "Refusing LLDPQ_SRC removal: Git worktree root could not be verified" >&2
        return 1
    }
    top=$(canonical_path "$top") || return 1
    [[ "$top" == "$source_path" ]] || {
        echo "Refusing LLDPQ_SRC removal: Git top-level differs from provenance path" >&2
        return 1
    }
    git_dir=$(sudo -H -u "$user" env GIT_OPTIONAL_LOCKS=0 LC_ALL=C \
        "$git_bin" -C "$source_path" rev-parse --absolute-git-dir 2>/dev/null) || {
        echo "Refusing LLDPQ_SRC removal: Git metadata directory could not be verified" >&2
        return 1
    }
    git_dir=$(canonical_path "$git_dir") || return 1
    [[ "$git_dir" == "$source_path/.git" ]] || {
        echo "Refusing LLDPQ_SRC removal: linked/external Git metadata is not supported" >&2
        return 1
    }
    counts=$(sudo -H -u "$user" env GIT_OPTIONAL_LOCKS=0 LC_ALL=C \
        "$git_bin" -C "$source_path" status --porcelain=v1 \
        --untracked-files=all 2>/dev/null | \
        awk 'length($0) >= 2 { if (substr($0,1,2) == "??") u++; else t++ }
             END { printf "%d %d\n", t+0, u+0 }') || {
        echo "Refusing LLDPQ_SRC removal: Git dirty/untracked state could not be inspected" >&2
        return 1
    }
    read -r SOURCE_GIT_TRACKED_CHANGES SOURCE_GIT_UNTRACKED <<< "$counts"
    [[ "$SOURCE_GIT_TRACKED_CHANGES" =~ ^[0-9]+$ && \
       "$SOURCE_GIT_UNTRACKED" =~ ^[0-9]+$ ]]
}

assert_lldpq_install_tree() {
    local path="$1"
    [[ -d "$path" ]] || return 0
    [[ -f "$path/devices.yaml" && -f "$path/monitor.sh" ]] || {
        echo "Unrecognized or partial LLDPq directory: '$path'" >&2
        return 1
    }
}

filter_legacy_lldpq_crontab() {
    local input_file="$1" output_file="$2" install_dir="$3"
    awk -v install_dir="$install_dir" '
        function owned(line) {
            return line ~ /\/usr\/local\/bin\/lldpq([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/lldpq-trigger([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/lldpq-ai-analyze([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/lldpq-provision-scheduler([[:space:]]|$)/ ||
                   line ~ /\/usr\/local\/bin\/get-conf([[:space:]]|$)/ ||
                   index(line, install_dir "/fabric-scan.sh") > 0 ||
                   (index(line, install_dir) > 0 && index(line, "./fabric-scan.sh") > 0) ||
                   index(line, install_dir "/fabric-scan-cron.sh") > 0 ||
                   (index(line, install_dir) > 0 && index(line, "./fabric-scan-cron.sh") > 0) ||
                   (index(line, install_dir) > 0 && index(line, "topology.dot.bkp") > 0)
        }
        !owned($0) { print }
    ' "$input_file" > "$output_file"
}

native_recovery_namespace_present() {
    local user="$1" home state
    home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
    [[ -n "$home" && "$home" == /* && "$home" != "/" ]] || return 0
    state="$home/.lldpq-state"
    [[ ! -L "$state" ]] || return 0
    [[ -d "$state" ]] || return 1
    sudo find -P "$state" -mindepth 1 -maxdepth 1 \
        \( -name '.backup-import-recovery' -o \
           -name '.backup-import-recovery.tmp-*' -o \
           -name '.backup-import-recovery.committed-*' -o \
           -name '.backup-import-recovery.rolled-back-*' \) \
        -print -quit 2>/dev/null | grep -q .
}

if [[ "${LLDPQ_UNINSTALL_LIB_ONLY:-false}" == "true" ]]; then
    return 0 2>/dev/null || exit 0
fi

# ─── Args ──────────────────────────────────────────────────────────────
AUTO_YES=false
DRY_RUN=false
KEEP_DATA=false
REMOVE_DHCP=false
REMOVE_NGINX_PKG=false
REMOVE_DOCKER_PKG=false
REMOVE_SOURCE=false
FORCE_PARTIAL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes) AUTO_YES=true ;;
        --dry-run) DRY_RUN=true ;;
        --keep-data) KEEP_DATA=true ;;
        --remove-dhcp) REMOVE_DHCP=true ;;
        --remove-nginx) REMOVE_NGINX_PKG=true ;;
        --remove-docker) REMOVE_DOCKER_PKG=true ;;
        --remove-source) REMOVE_SOURCE=true ;;
        --force-partial) FORCE_PARTIAL=true ;;
        -h|--help)
            sed -n '1,35p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ─── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

# The web gateway tails the transient unit's journal.  Emit one terminal
# record for both success and failure so a quickly collected systemd unit does
# not make an unsuccessful uninstall look merely "disconnected".
emit_uninstall_exit_marker() {
    local rc=$?
    trap - EXIT
    trap '' HUP INT TERM
    if [[ "$rc" -ne 0 && -n "${QUIESCE_ROLLBACK_DIR:-}" ]] && \
       declare -F rollback_keep_data_quiesce >/dev/null 2>&1; then
        rollback_keep_data_quiesce || true
    fi
    if ! $DRY_RUN; then
        printf '__LLDPQ_UNINSTALL_DONE__:%s\n' "$rc"
    fi
    exit "$rc"
}
trap emit_uninstall_exit_marker EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

run() {
    if $DRY_RUN; then
        echo "DRY-RUN  $*"
    else
        eval "$@"
    fi
}

UNINSTALL_INCOMPLETE=false
declare -a UNINSTALL_FAILURE_MESSAGES=()

record_cleanup_failure() {
    local message="$1"
    UNINSTALL_INCOMPLETE=true
    UNINSTALL_FAILURE_MESSAGES+=("$message")
    echo "[!] $message" >&2
}

report_cleanup_failures() {
    echo "" >&2
    echo "[!] LLDPq uninstall is incomplete; mandatory cleanup failures:" >&2
    local failure
    for failure in "${UNINSTALL_FAILURE_MESSAGES[@]}"; do
        echo "    - $failure" >&2
    done
    echo "    Inspect the host and repair/remove the listed residues before retrying." >&2
}

run_required() {
    local label="$1" command="$2"
    if ! run "$command"; then
        record_cleanup_failure "$label"
        return 1
    fi
}

verify_absent() {
    local label="$1"
    shift
    $DRY_RUN && return 0
    local path
    for path in "$@"; do
        if [[ -e "$path" || -L "$path" ]]; then
            record_cleanup_failure "$label remains: $path"
            return 1
        fi
    done
}

remove_native_lldpq_state() {
    local user="$1"
    local action="remove"
    $DRY_RUN && action="validate"

    # Setup run/update logs, backup-import recovery and config-collection history
    # all live in this dedicated namespace. Validate the complete tree before a
    # descriptor-relative removal; never follow a substituted symlink or mount.
    sudo python3 - "$action" "$user" <<'PYTHON_REMOVE_NATIVE_STATE'
import os
import pwd
import stat
import sys


def open_directory(name, *, dir_fd=None):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=dir_fd)


def mount_points():
    def decode(value):
        for encoded, decoded in (
            ("\\040", " "), ("\\011", "\t"),
            ("\\012", "\n"), ("\\134", "\\"),
        ):
            value = value.replace(encoded, decoded)
        return os.path.normpath(value)

    with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
        for line in handle:
            fields = line.split(" - ", 1)[0].split()
            if len(fields) >= 5:
                yield decode(fields[4])


def validate_metadata(metadata, account, device, name, *, directory=False):
    expected_type = stat.S_ISDIR(metadata.st_mode) if directory else (
        stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
    )
    if not expected_type:
        raise RuntimeError("unsupported special entry in .lldpq-state: " + name)
    if metadata.st_dev != device:
        raise RuntimeError(".lldpq-state crosses a filesystem boundary: " + name)
    if metadata.st_uid != account.pw_uid:
        raise RuntimeError("foreign-owned entry in .lldpq-state: " + name)
    # An interior symlink is never followed and is removed with unlinkat(2).
    # Linux reports symlink modes as 0777, so applying the writable-bit rule to
    # the link itself would reject every otherwise safe link.  GID is likewise
    # not deletion authority: service-user files may legitimately inherit a
    # setgid home/team group. UID ownership plus non-writable real entries is
    # the stable native contract.
    if not stat.S_ISLNK(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise RuntimeError("group/world-writable entry in .lldpq-state: " + name)


def validate_tree(directory_fd, account, device, budget):
    for name in os.listdir(directory_fd):
        if name in (".", "..") or "/" in name or "\x00" in name:
            raise RuntimeError("invalid .lldpq-state entry")
        budget[0] += 1
        if budget[0] > 1_000_000:
            raise RuntimeError(".lldpq-state contains too many entries")
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            validate_metadata(metadata, account, device, name, directory=True)
            child_fd = open_directory(name, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (
                    metadata.st_dev, metadata.st_ino
                ):
                    raise RuntimeError(".lldpq-state directory changed: " + name)
                validate_tree(child_fd, account, device, budget)
            finally:
                os.close(child_fd)
        else:
            validate_metadata(metadata, account, device, name)


def remove_tree(directory_fd, account, device, budget):
    while True:
        names = os.listdir(directory_fd)
        if not names:
            break
        for name in names:
            if name in (".", "..") or "/" in name or "\x00" in name:
                raise RuntimeError("invalid .lldpq-state entry")
            budget[0] += 1
            if budget[0] > 1_000_000:
                raise RuntimeError(".lldpq-state contains too many entries")
            try:
                metadata = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(metadata.st_mode):
                validate_metadata(metadata, account, device, name, directory=True)
                child_fd = open_directory(name, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (
                        metadata.st_dev, metadata.st_ino
                    ):
                        raise RuntimeError(".lldpq-state directory changed: " + name)
                    remove_tree(child_fd, account, device, budget)
                finally:
                    os.close(child_fd)
                current = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) != (
                    metadata.st_dev, metadata.st_ino
                ):
                    raise RuntimeError(".lldpq-state directory was replaced: " + name)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                validate_metadata(metadata, account, device, name)
                current = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) != (
                    metadata.st_dev, metadata.st_ino
                ):
                    raise RuntimeError(".lldpq-state entry was replaced: " + name)
                os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


action, user = sys.argv[1:]
if action not in ("validate", "remove"):
    raise RuntimeError("unsupported .lldpq-state cleanup action")
account = pwd.getpwnam(user)
home = account.pw_dir
if (
    not os.path.isabs(home)
    or home == "/"
    or "\x00" in home
    or os.path.realpath(home) != home
):
    raise RuntimeError("unsafe service-account home")

home_fd = open_directory(home)
try:
    home_metadata = os.fstat(home_fd)
    if not stat.S_ISDIR(home_metadata.st_mode) or home_metadata.st_uid != account.pw_uid:
        raise RuntimeError("untrusted service-account home")
    try:
        state_fd = open_directory(".lldpq-state", dir_fd=home_fd)
    except FileNotFoundError:
        raise SystemExit(0)
    try:
        state_metadata = os.fstat(state_fd)
        validate_metadata(
            state_metadata, account, state_metadata.st_dev,
            ".lldpq-state", directory=True,
        )
        state_path = os.path.join(home, ".lldpq-state")
        for point in mount_points():
            if point == state_path or point.startswith(state_path + "/"):
                raise RuntimeError("mount point below .lldpq-state: " + point)
        validate_tree(state_fd, account, state_metadata.st_dev, [0])
        if action == "remove":
            remove_tree(state_fd, account, state_metadata.st_dev, [0])
    finally:
        os.close(state_fd)
    if action == "remove":
        current = os.stat(".lldpq-state", dir_fd=home_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
            state_metadata.st_dev, state_metadata.st_ino
        ):
            raise RuntimeError(".lldpq-state was replaced before final removal")
        os.rmdir(".lldpq-state", dir_fd=home_fd)
        os.fsync(home_fd)
finally:
    os.close(home_fd)
PYTHON_REMOVE_NATIVE_STATE

    if $DRY_RUN; then
        echo "DRY-RUN  validated safe removal of the dedicated ~${user}/.lldpq-state tree"
    fi
}

remove_native_lldpq_fixed_tree() {
    local user="$1" target="$2"
    local action="remove"
    case "$target" in
        /var/log/lldpq|/var/lib/lldpq|/tmp/ansible-www|/tmp/ansible-tmp|/tmp/ansible-cache) ;;
        *) return 1 ;;
    esac
    $DRY_RUN && action="validate"

    sudo python3 - "$action" "$user" "$target" <<'PYTHON_REMOVE_NATIVE_TREE'
import os
import pwd
import stat
import sys


def open_directory(name, *, dir_fd=None):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=dir_fd)


def mount_points():
    def decode(value):
        for encoded, decoded in (
            ("\\040", " "), ("\\011", "\t"),
            ("\\012", "\n"), ("\\134", "\\"),
        ):
            value = value.replace(encoded, decoded)
        return os.path.normpath(value)

    with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
        for line in handle:
            fields = line.split(" - ", 1)[0].split()
            if len(fields) >= 5:
                yield decode(fields[4])


def validate_tree(directory_fd, device, allowed_uids, budget):
    for name in os.listdir(directory_fd):
        if name in (".", "..") or "/" in name or "\x00" in name:
            raise RuntimeError("invalid LLDPq tree entry")
        budget[0] += 1
        if budget[0] > 1_000_000:
            raise RuntimeError("LLDPq tree contains too many entries")
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if metadata.st_dev != device or metadata.st_uid not in allowed_uids:
            raise RuntimeError("foreign/cross-device LLDPq tree entry: " + name)
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = open_directory(name, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (
                    metadata.st_dev, metadata.st_ino
                ):
                    raise RuntimeError("LLDPq tree directory changed: " + name)
                validate_tree(child_fd, device, allowed_uids, budget)
            finally:
                os.close(child_fd)
        elif not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise RuntimeError("unsafe non-regular LLDPq tree entry: " + name)


def remove_tree(directory_fd, device, allowed_uids, budget):
    while True:
        names = os.listdir(directory_fd)
        if not names:
            break
        for name in names:
            if name in (".", "..") or "/" in name or "\x00" in name:
                raise RuntimeError("invalid LLDPq tree entry")
            budget[0] += 1
            if budget[0] > 1_000_000:
                raise RuntimeError("LLDPq tree contains too many entries")
            try:
                metadata = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
            except FileNotFoundError:
                continue
            if metadata.st_dev != device or metadata.st_uid not in allowed_uids:
                raise RuntimeError("foreign/cross-device LLDPq tree entry: " + name)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = open_directory(name, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (
                        metadata.st_dev, metadata.st_ino
                    ):
                        raise RuntimeError("LLDPq tree directory changed: " + name)
                    remove_tree(child_fd, device, allowed_uids, budget)
                finally:
                    os.close(child_fd)
                current = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) != (
                    metadata.st_dev, metadata.st_ino
                ):
                    raise RuntimeError("LLDPq tree directory was replaced: " + name)
                os.rmdir(name, dir_fd=directory_fd)
            elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                current = os.stat(
                    name, dir_fd=directory_fd, follow_symlinks=False
                )
                if (current.st_dev, current.st_ino) != (
                    metadata.st_dev, metadata.st_ino
                ):
                    raise RuntimeError("LLDPq tree file was replaced: " + name)
                os.unlink(name, dir_fd=directory_fd)
            else:
                raise RuntimeError("unsafe non-regular LLDPq tree entry: " + name)
    os.fsync(directory_fd)


action, user, target = sys.argv[1:]
if action not in ("validate", "remove"):
    raise RuntimeError("unsupported fixed-tree cleanup action")
runtime_user = pwd.getpwnam(user)
if target not in (
    "/var/log/lldpq", "/var/lib/lldpq",
    "/tmp/ansible-www", "/tmp/ansible-tmp", "/tmp/ansible-cache",
):
    raise RuntimeError("unexpected fixed LLDPq tree")
parent_path = os.path.dirname(target)
leaf = os.path.basename(target)
allowed_uids = {0, runtime_user.pw_uid}
for name in ("www-data", "syslog"):
    try:
        allowed_uids.add(pwd.getpwnam(name).pw_uid)
    except KeyError:
        pass

parent_fd = open_directory(parent_path)
try:
    parent_metadata = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent_metadata.st_uid != 0:
        raise RuntimeError(parent_path + " is not a trusted root-owned directory")
    try:
        target_metadata = os.stat(
            leaf, dir_fd=parent_fd, follow_symlinks=False
        )
    except FileNotFoundError:
        raise SystemExit(0)
    if (
        not stat.S_ISDIR(target_metadata.st_mode)
        or target_metadata.st_uid not in allowed_uids
    ):
        raise RuntimeError(target + " is not a trusted directory")
    for point in mount_points():
        if point == target or point.startswith(target + "/"):
            raise RuntimeError("mount point below " + target + ": " + point)
    target_fd = open_directory(leaf, dir_fd=parent_fd)
    try:
        opened = os.fstat(target_fd)
        if (opened.st_dev, opened.st_ino) != (
            target_metadata.st_dev, target_metadata.st_ino
        ):
            raise RuntimeError(target + " changed while it was opened")
        validate_tree(target_fd, opened.st_dev, allowed_uids, [0])
        if action == "remove":
            remove_tree(target_fd, opened.st_dev, allowed_uids, [0])
    finally:
        os.close(target_fd)
    if action == "remove":
        current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
            target_metadata.st_dev, target_metadata.st_ino
        ):
            raise RuntimeError(target + " was replaced before final removal")
        os.rmdir(leaf, dir_fd=parent_fd)
        os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PYTHON_REMOVE_NATIVE_TREE

    if $DRY_RUN; then
        echo "DRY-RUN  validated safe removal of $target"
    fi
}

remove_fixed_lldpq_temp_files() {
    local user="$1" phase="${2:-all}"
    local action="remove"
    local -a paths=(
        /tmp/lldpq-monitor.lock
        /tmp/lldpq-get-configs.lock
        /tmp/lldpq-fabric-scan.lock
        /tmp/lldpq-trigger-daemon.lock
        /tmp/lldpq-console-audit.log
        /tmp/ansible-gitconfig
        /tmp/.monitor_web_trigger
        /tmp/.configs_web_trigger
        /tmp/.transceiver_web_trigger
        /tmp/.assets_refresh_trigger
        /tmp/lldp_trigger_daemon.pid
        /tmp/configs_running.lock
        /tmp/fabric-scan.log
    )
    case "$phase" in
        all|defer-monitor|monitor-only) ;;
        *) return 1 ;;
    esac
    $DRY_RUN && action="validate"

    sudo python3 - "$action" "$phase" "$user" "${paths[@]}" <<'PYTHON_REMOVE_TEMP_FILES'
import os
import pwd
import re
import stat
import sys


action, phase = sys.argv[1:3]
if action not in ("validate", "remove"):
    raise RuntimeError("unsupported temporary-artifact cleanup action")
if phase not in ("all", "defer-monitor", "monitor-only"):
    raise RuntimeError("unsupported temporary-artifact cleanup phase")
runtime_user = pwd.getpwnam(sys.argv[3])
allowed_uids = {0, runtime_user.pw_uid}
for name in ("www-data", "syslog"):
    try:
        allowed_uids.add(pwd.getpwnam(name).pw_uid)
    except KeyError:
        pass

flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open("/tmp", flags)
try:
    parent = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or not stat.S_IMODE(parent.st_mode) & stat.S_ISVTX
    ):
        raise RuntimeError("/tmp is not a trusted root-owned sticky directory")
    paths = list(sys.argv[4:])
    dynamic_artifact = re.compile(
        r"(?:"
        r"lldpq-(?:start-clsupport|run-device-command)-"
        r"[A-Za-z0-9_-]{0,48}_[0-9a-f]{16}\.lock|"
        r"\.(?:monitor|configs|transceiver)_web_trigger\.tmp\.[0-9]+\.[0-9]+|"
        r"lldp_trigger_daemon\.pid\.tmp\.[0-9]+|"
        r"lldpq-setup-request\.[A-Za-z0-9]{6}|"
        r"lldpq-upload-src\.[A-Za-z0-9]{6}\.tar\.gz"
        r")\Z"
    )
    if phase != "monitor-only":
        for name in os.listdir(parent_fd):
            if dynamic_artifact.fullmatch(name):
                paths.append("/tmp/" + name)
    validated = []
    for path in paths:
        is_monitor = path == "/tmp/lldpq-monitor.lock"
        if phase == "monitor-only" and not is_monitor:
            continue
        if os.path.dirname(path) != "/tmp":
            raise RuntimeError("unexpected temp cleanup path")
        name = os.path.basename(path)
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if metadata.st_uid not in allowed_uids:
            raise RuntimeError("foreign-owned LLDPq temp artifact: " + path)
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                raise RuntimeError("hard-linked LLDPq temp artifact: " + path)
        elif not stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError("unexpected LLDPq temp artifact type: " + path)
        validated.append((path, name, (
            metadata.st_dev, metadata.st_ino, metadata.st_uid,
            stat.S_IFMT(metadata.st_mode), metadata.st_nlink,
        )))
    if action == "remove":
        for path, name, expected in validated:
            is_monitor = path == "/tmp/lldpq-monitor.lock"
            if phase == "defer-monitor" and is_monitor:
                continue
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            identity = (
                current.st_dev, current.st_ino, current.st_uid,
                stat.S_IFMT(current.st_mode), current.st_nlink,
            )
            if identity != expected:
                raise RuntimeError("LLDPq temp artifact changed before removal: " + path)
        for path, name, _expected in validated:
            is_monitor = path == "/tmp/lldpq-monitor.lock"
            if not (phase == "defer-monitor" and is_monitor):
                os.unlink(name, dir_fd=parent_fd)
        if phase != "monitor-only" and any(
            dynamic_artifact.fullmatch(name) for name in os.listdir(parent_fd)
        ):
            raise RuntimeError("dynamic LLDPq temporary artifact reappeared during cleanup")
        os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PYTHON_REMOVE_TEMP_FILES

    if $DRY_RUN; then
        if [[ "$phase" == "monitor-only" ]]; then
            echo "DRY-RUN  validated safe removal of fixed LLDPq temp artifact: /tmp/lldpq-monitor.lock"
        else
            printf 'DRY-RUN  validated safe removal of fixed LLDPq temp artifact: %s\n' "${paths[@]}"
            echo "DRY-RUN  validated matching LLDPq request stages and per-device locks under /tmp"
        fi
    fi
}

remove_managed_web_runtime_residue() {
    local user="$1" web_root="$2" action="remove"
    $DRY_RUN && action="validate"

    # Support-bundle downloads are generated below WEB_ROOT/downloads, while
    # monitor.sh atomically publishes through a hidden sibling tree.  Both can
    # survive a hard kill. Validate every managed candidate before mutation,
    # walk staging trees descriptor-relative without following symlinks, and
    # leave unrelated files in a shared downloads/ directory untouched.
    sudo python3 - "$action" "$user" "$web_root" <<'PYTHON_REMOVE_WEB_RUNTIME'
import os
import pwd
import re
import stat
import sys


def open_directory(name, *, dir_fd=None):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.open(name, flags, dir_fd=dir_fd)


def mount_points():
    def decode(value):
        for encoded, decoded in (
            ("\\040", " "), ("\\011", "\t"),
            ("\\012", "\n"), ("\\134", "\\"),
        ):
            value = value.replace(encoded, decoded)
        return os.path.normpath(value)

    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as handle:
            for line in handle:
                fields = line.split(" - ", 1)[0].split()
                if len(fields) >= 5:
                    yield decode(fields[4])
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("mount topology could not be inspected safely") from exc


def identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_uid,
        stat.S_IFMT(metadata.st_mode), metadata.st_nlink,
    )


def validate_tree(directory_fd, device, allowed_uids, budget):
    for name in os.listdir(directory_fd):
        if name in (".", "..") or "/" in name or "\x00" in name:
            raise RuntimeError("invalid monitor web-stage entry")
        budget[0] += 1
        if budget[0] > 1_000_000:
            raise RuntimeError("monitor web stage contains too many entries")
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if metadata.st_dev != device or metadata.st_uid not in allowed_uids:
            raise RuntimeError("foreign/cross-device monitor web-stage entry: " + name)
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = open_directory(name, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                if identity(opened)[:2] != identity(metadata)[:2]:
                    raise RuntimeError("monitor web-stage directory changed: " + name)
                validate_tree(child_fd, device, allowed_uids, budget)
            finally:
                os.close(child_fd)
        elif not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise RuntimeError("unsupported monitor web-stage entry: " + name)


def remove_tree(directory_fd, device, allowed_uids, budget):
    while True:
        names = os.listdir(directory_fd)
        if not names:
            break
        for name in names:
            if name in (".", "..") or "/" in name or "\x00" in name:
                raise RuntimeError("invalid monitor web-stage entry")
            budget[0] += 1
            if budget[0] > 1_000_000:
                raise RuntimeError("monitor web stage contains too many entries")
            try:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if metadata.st_dev != device or metadata.st_uid not in allowed_uids:
                raise RuntimeError("foreign/cross-device monitor web-stage entry: " + name)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = open_directory(name, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if identity(opened)[:2] != identity(metadata)[:2]:
                        raise RuntimeError("monitor web-stage directory changed: " + name)
                    remove_tree(child_fd, device, allowed_uids, budget)
                finally:
                    os.close(child_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if identity(current)[:2] != identity(metadata)[:2]:
                    raise RuntimeError("monitor web-stage directory was replaced: " + name)
                os.rmdir(name, dir_fd=directory_fd)
            elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if identity(current)[:2] != identity(metadata)[:2]:
                    raise RuntimeError("monitor web-stage entry was replaced: " + name)
                os.unlink(name, dir_fd=directory_fd)
            else:
                raise RuntimeError("unsupported monitor web-stage entry: " + name)
    os.fsync(directory_fd)


action, user, web_root = sys.argv[1:]
if action not in ("validate", "remove"):
    raise RuntimeError("unsupported web-runtime cleanup action")
if (
    not os.path.isabs(web_root)
    or web_root == "/"
    or any(character in web_root for character in "\x00\r\n")
    or os.path.realpath(web_root) != web_root
):
    raise RuntimeError("unsafe web root for runtime cleanup")

runtime_user = pwd.getpwnam(user)
allowed_uids = {0, runtime_user.pw_uid}
try:
    allowed_uids.add(pwd.getpwnam("www-data").pw_uid)
except KeyError:
    pass

stage_pattern = re.compile(
    r"\.monitor-results\.new\.[A-Za-z0-9]{10}(?:\.previous)?\Z"
)
download_pattern = re.compile(
    r"(?:\.download-[A-Za-z0-9._-]{1,220}|"
    r"lldpq-[A-Za-z0-9._-]{1,220}\.(?:tar\.xz|tar\.gz|pcap|txz))\Z"
)
mounts = tuple(mount_points())

web_fd = open_directory(web_root)
try:
    web_metadata = os.fstat(web_fd)
    if not stat.S_ISDIR(web_metadata.st_mode) or web_metadata.st_uid not in allowed_uids:
        raise RuntimeError("web root failed its ownership/type check")

    stages = []
    for name in os.listdir(web_fd):
        if not stage_pattern.fullmatch(name):
            continue
        metadata = os.stat(name, dir_fd=web_fd, follow_symlinks=False)
        stage_path = os.path.join(web_root, name)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_dev != web_metadata.st_dev
            or metadata.st_uid not in allowed_uids
        ):
            raise RuntimeError("unsafe monitor web stage: " + stage_path)
        if any(point == stage_path or point.startswith(stage_path + "/") for point in mounts):
            raise RuntimeError("mount point below monitor web stage: " + stage_path)
        stage_fd = open_directory(name, dir_fd=web_fd)
        try:
            opened = os.fstat(stage_fd)
            if identity(opened)[:2] != identity(metadata)[:2]:
                raise RuntimeError("monitor web stage changed while opening: " + stage_path)
            validate_tree(stage_fd, opened.st_dev, allowed_uids, [0])
        finally:
            os.close(stage_fd)
        stages.append((name, identity(metadata)))

    downloads = None
    try:
        downloads_metadata = os.stat(
            "downloads", dir_fd=web_fd, follow_symlinks=False
        )
    except FileNotFoundError:
        pass
    else:
        downloads_path = os.path.join(web_root, "downloads")
        if (
            not stat.S_ISDIR(downloads_metadata.st_mode)
            or downloads_metadata.st_dev != web_metadata.st_dev
            or downloads_metadata.st_uid not in allowed_uids
        ):
            raise RuntimeError("unsafe managed downloads directory: " + downloads_path)
        if any(
            point == downloads_path or point.startswith(downloads_path + "/")
            for point in mounts
        ):
            raise RuntimeError("mount point below managed downloads directory")
        downloads_fd = open_directory("downloads", dir_fd=web_fd)
        try:
            opened = os.fstat(downloads_fd)
            if identity(opened)[:2] != identity(downloads_metadata)[:2]:
                raise RuntimeError("managed downloads directory changed while opening")
            managed = []
            for name in os.listdir(downloads_fd):
                if not download_pattern.fullmatch(name):
                    continue
                metadata = os.stat(
                    name, dir_fd=downloads_fd, follow_symlinks=False
                )
                if metadata.st_dev != opened.st_dev or metadata.st_uid not in allowed_uids:
                    raise RuntimeError("foreign/cross-device managed download: " + name)
                if stat.S_ISREG(metadata.st_mode):
                    if metadata.st_nlink != 1:
                        raise RuntimeError("hard-linked managed download: " + name)
                elif not stat.S_ISLNK(metadata.st_mode):
                    raise RuntimeError("unsupported managed download type: " + name)
                managed.append((name, identity(metadata)))
            downloads = (identity(downloads_metadata), managed)
        finally:
            os.close(downloads_fd)

    if action == "remove":
        # All candidates have passed once; re-open/revalidate immediately
        # before mutation so a failed candidate cannot cause partial cleanup.
        for name, expected in stages:
            current = os.stat(name, dir_fd=web_fd, follow_symlinks=False)
            if identity(current) != expected:
                raise RuntimeError("monitor web stage changed before removal: " + name)
            stage_fd = open_directory(name, dir_fd=web_fd)
            try:
                validate_tree(stage_fd, current.st_dev, allowed_uids, [0])
                remove_tree(stage_fd, current.st_dev, allowed_uids, [0])
            finally:
                os.close(stage_fd)
            final = os.stat(name, dir_fd=web_fd, follow_symlinks=False)
            if identity(final)[:2] != identity(current)[:2]:
                raise RuntimeError("monitor web stage was replaced: " + name)
            os.rmdir(name, dir_fd=web_fd)

        if downloads is not None:
            expected_root, managed = downloads
            current_root = os.stat(
                "downloads", dir_fd=web_fd, follow_symlinks=False
            )
            if identity(current_root) != expected_root:
                raise RuntimeError("managed downloads directory changed before removal")
            downloads_fd = open_directory("downloads", dir_fd=web_fd)
            try:
                for name, expected in managed:
                    current = os.stat(
                        name, dir_fd=downloads_fd, follow_symlinks=False
                    )
                    if identity(current) != expected:
                        raise RuntimeError("managed download changed before removal: " + name)
                for name, _expected in managed:
                    os.unlink(name, dir_fd=downloads_fd)
                if any(
                    download_pattern.fullmatch(name)
                    for name in os.listdir(downloads_fd)
                ):
                    raise RuntimeError("managed download reappeared during cleanup")
                downloads_empty = not os.listdir(downloads_fd)
                os.fsync(downloads_fd)
            finally:
                os.close(downloads_fd)
            if downloads_empty:
                final_root = os.stat(
                    "downloads", dir_fd=web_fd, follow_symlinks=False
                )
                if identity(final_root) != expected_root:
                    raise RuntimeError("managed downloads directory was replaced")
                os.rmdir("downloads", dir_fd=web_fd)

        if any(stage_pattern.fullmatch(name) for name in os.listdir(web_fd)):
            raise RuntimeError("monitor web stage reappeared during cleanup")
        os.fsync(web_fd)
finally:
    os.close(web_fd)
PYTHON_REMOVE_WEB_RUNTIME

    if $DRY_RUN; then
        echo "DRY-RUN  validated managed support downloads under $web_root/downloads and monitor web stages"
    else
        echo "  managed support downloads under $web_root/downloads and monitor web stages cleaned"
    fi
}

remove_managed_provision_root_artifacts() {
    local path name target artifact_name
    local -a image_candidates onie_aliases rollback_candidates onie_temp_candidates

    # Provision historically stored uploaded images as regular top-level
    # WEB_ROOT files.  Current releases store them in provision-uploads/ and
    # publish an exact relative compatibility symlink.  Restrict cleanup to
    # those three reserved image extensions and to the current/legacy reserved
    # ONIE alias names; unrelated web-root content and symlinks survive.
    shopt -s nullglob
    image_candidates=("$WEB_ROOT"/*.bin "$WEB_ROOT"/*.img "$WEB_ROOT"/*.iso)
    shopt -u nullglob
    for path in "${image_candidates[@]}"; do
        name=$(basename -- "$path")
        if [[ -L "$path" ]]; then
            target=$(readlink -- "$path" 2>/dev/null || true)
            if [[ "$target" != "provision-uploads/$name" ]]; then
                case "$name" in
                    onie-installer.bin|onie-installer-x86_64.bin|onie-installer-x86_64-mlnx.bin)
                        # Reserved legacy ONIE names may point directly to the
                        # selected image rather than provision-uploads/.
                        ;;
                    *)
                        echo "  left unrelated image-named symlink: $path"
                        continue
                        ;;
                esac
            fi
        elif [[ ! -f "$path" ]]; then
            echo "  left non-regular image-named web artifact: $path"
            continue
        fi
        if $DRY_RUN; then
            echo "DRY-RUN  sudo rm -f -- $path"
        elif sudo rm -f -- "$path"; then
            echo "  removed provision image artifact $path"
        else
            record_cleanup_failure "Provision image artifact could not be removed: $path"
        fi
    done

    onie_aliases=(
        "$WEB_ROOT/onie-installer-x86_64"
        "$WEB_ROOT/onie-installer-x86_64-mlnx"
        "$WEB_ROOT/onie-installer"
        "$WEB_ROOT/onie-installer-x86_64.bin"
        "$WEB_ROOT/onie-installer-x86_64-mlnx.bin"
        "$WEB_ROOT/onie-installer.bin"
    )
    for path in "${onie_aliases[@]}"; do
        [[ -L "$path" ]] || continue
        if $DRY_RUN; then
            echo "DRY-RUN  sudo rm -f -- $path"
        elif sudo rm -f -- "$path"; then
            echo "  removed provision ONIE alias $path"
        else
            record_cleanup_failure "Provision ONIE alias could not be removed: $path"
        fi
    done

    # publish_uploaded_image() may be killed after hard-linking a legacy
    # WEB_ROOT image but before its finally block. Match only its exact current
    # rollback basename contract: .<valid image>.rollback-<pid>-<uuid32>.
    shopt -s nullglob
    rollback_candidates=("$WEB_ROOT"/.*.rollback-*)
    shopt -u nullglob
    for path in "${rollback_candidates[@]}"; do
        artifact_name=$(basename -- "$path")
        [[ "$artifact_name" =~ ^\.[A-Za-z0-9_.-]+\.(bin|img|iso)\.rollback-[1-9][0-9]*-[0-9a-f]{32}$ ]] || continue
        if [[ -L "$path" || ! -f "$path" ]]; then
            record_cleanup_failure "Refused unexpected Provision image rollback artifact type: $path"
            continue
        fi
        if $DRY_RUN; then
            echo "DRY-RUN  sudo rm -f -- $path"
        elif sudo rm -f -- "$path"; then
            echo "  removed stranded Provision image rollback $path"
        else
            record_cleanup_failure "Provision image rollback could not be removed: $path"
        fi
    done

    # _publish_symlink() stages only these reserved ONIE aliases using a UUID
    # sibling before os.replace(). A killed worker may strand the symlink.
    shopt -s nullglob
    onie_temp_candidates=("$WEB_ROOT"/.onie-installer*.tmp)
    shopt -u nullglob
    for path in "${onie_temp_candidates[@]}"; do
        artifact_name=$(basename -- "$path")
        [[ "$artifact_name" =~ ^\.(onie-installer|onie-installer-x86_64|onie-installer-x86_64-mlnx)\.[0-9a-f]{32}\.tmp$ ]] || continue
        if [[ ! -L "$path" ]]; then
            record_cleanup_failure "Refused unexpected Provision ONIE staging artifact type: $path"
            continue
        fi
        if $DRY_RUN; then
            echo "DRY-RUN  sudo rm -f -- $path"
        elif sudo rm -f -- "$path"; then
            echo "  removed stranded Provision ONIE stage $path"
        else
            record_cleanup_failure "Provision ONIE staging symlink could not be removed: $path"
        fi
    done
}

verify_managed_provision_root_artifacts_absent() {
    $DRY_RUN && return 0
    local path name target artifact_name
    local -a image_candidates onie_aliases rollback_candidates onie_temp_candidates

    shopt -s nullglob
    image_candidates=("$WEB_ROOT"/*.bin "$WEB_ROOT"/*.img "$WEB_ROOT"/*.iso)
    shopt -u nullglob
    for path in "${image_candidates[@]}"; do
        if [[ -f "$path" && ! -L "$path" ]]; then
            record_cleanup_failure "Legacy provision image remains: $path"
            continue
        fi
        if [[ -L "$path" ]]; then
            name=$(basename -- "$path")
            target=$(readlink -- "$path" 2>/dev/null || true)
            if [[ "$target" == "provision-uploads/$name" ]]; then
                record_cleanup_failure "Provision image compatibility link remains: $path"
            fi
        fi
    done
    onie_aliases=(
        "$WEB_ROOT/onie-installer-x86_64"
        "$WEB_ROOT/onie-installer-x86_64-mlnx"
        "$WEB_ROOT/onie-installer"
        "$WEB_ROOT/onie-installer-x86_64.bin"
        "$WEB_ROOT/onie-installer-x86_64-mlnx.bin"
        "$WEB_ROOT/onie-installer.bin"
    )
    for path in "${onie_aliases[@]}"; do
        [[ -L "$path" ]] && \
            record_cleanup_failure "Provision ONIE alias remains: $path"
    done
    shopt -s nullglob
    rollback_candidates=("$WEB_ROOT"/.*.rollback-*)
    shopt -u nullglob
    for path in "${rollback_candidates[@]}"; do
        artifact_name=$(basename -- "$path")
        if [[ "$artifact_name" =~ ^\.[A-Za-z0-9_.-]+\.(bin|img|iso)\.rollback-[1-9][0-9]*-[0-9a-f]{32}$ ]]; then
            record_cleanup_failure "Provision image rollback remains: $path"
        fi
    done
    shopt -s nullglob
    onie_temp_candidates=("$WEB_ROOT"/.onie-installer*.tmp)
    shopt -u nullglob
    for path in "${onie_temp_candidates[@]}"; do
        artifact_name=$(basename -- "$path")
        if [[ "$artifact_name" =~ ^\.(onie-installer|onie-installer-x86_64|onie-installer-x86_64-mlnx)\.[0-9a-f]{32}\.tmp$ ]]; then
            record_cleanup_failure "Provision ONIE staging artifact remains: $path"
        fi
    done
}

package_is_installed() {
    local package="$1" status
    command -v dpkg-query >/dev/null 2>&1 || return 1
    status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
    [[ "$status" == ii* ]]
}

step() {
    echo ""
    echo -e "${CYAN}→ $1${NC}"
}

acquire_uninstall_update_lock() {
    local lock_file="${LLDPQ_MONITOR_LOCK_FILE:-/tmp/lldpq-monitor.lock}"
    local wait_seconds="${LLDPQ_UNINSTALL_LOCK_TIMEOUT:-600}"
    local path_metadata fd_metadata final_metadata link_count
    UNINSTALL_UPDATE_LOCK_PATH="$lock_file"
    if $DRY_RUN; then
        echo "DRY-RUN  wait for and hold LLDPq update/collection lock: $lock_file"
        return 0
    fi
    [[ "$lock_file" == /* && "$lock_file" != *$'\n'* && "$lock_file" != *$'\r'* ]] || {
        echo "[!] Unsafe LLDPq update lock path: $lock_file" >&2
        return 1
    }
    case "$wait_seconds" in
        ''|*[!0-9]*|0) return 1 ;;
    esac
    if [[ -e "$lock_file" || -L "$lock_file" ]]; then
        [[ -f "$lock_file" && ! -L "$lock_file" ]] || {
            echo "[!] Refusing unsafe LLDPq update lock type: $lock_file" >&2
            return 1
        }
    fi
    # Append-open avoids truncating an existing lock inode. Compare the public
    # pathname with the opened descriptor before and after flock so a symlink,
    # hard link or sticky-/tmp rename race cannot become the serialization
    # authority used by the final uninstall commit.
    exec {UNINSTALL_UPDATE_LOCK_FD}>>"$lock_file" || return 1
    path_metadata=$(stat -c '%d:%i:%h' -- "$lock_file" 2>/dev/null || true)
    fd_metadata=$(stat -Lc '%d:%i:%h' -- \
        "/proc/$$/fd/$UNINSTALL_UPDATE_LOCK_FD" 2>/dev/null || true)
    link_count="${path_metadata##*:}"
    if [[ -z "$path_metadata" || "$path_metadata" != "$fd_metadata" || \
          "$link_count" != "1" || -L "$lock_file" || ! -f "$lock_file" ]]; then
        echo "[!] LLDPq update lock changed or is unsafe while opening: $lock_file" >&2
        exec {UNINSTALL_UPDATE_LOCK_FD}>&-
        UNINSTALL_UPDATE_LOCK_FD=""
        return 1
    fi
    if ! flock -w "$wait_seconds" "$UNINSTALL_UPDATE_LOCK_FD"; then
        echo "[!] Timed out waiting for an active LLDPq update" >&2
        exec {UNINSTALL_UPDATE_LOCK_FD}>&-
        UNINSTALL_UPDATE_LOCK_FD=""
        return 1
    fi
    final_metadata=$(stat -c '%d:%i:%h' -- "$lock_file" 2>/dev/null || true)
    if [[ "$final_metadata" != "$path_metadata" || -L "$lock_file" || \
          ! -f "$lock_file" ]]; then
        echo "[!] LLDPq update lock changed while waiting: $lock_file" >&2
        exec {UNINSTALL_UPDATE_LOCK_FD}>&-
        UNINSTALL_UPDATE_LOCK_FD=""
        return 1
    fi
}

acquire_uninstall_config_collection_lock() {
    local lock_file="/tmp/lldpq-get-configs.lock"
    local wait_seconds="${LLDPQ_UNINSTALL_LOCK_TIMEOUT:-600}"
    local expected_uid before_metadata after_metadata fd_metadata
    local lock_uid lock_links tmp_uid tmp_mode

    if $DRY_RUN; then
        echo "DRY-RUN  wait for and hold LLDPq config-collection lock: $lock_file"
        return 0
    fi
    command -v flock >/dev/null 2>&1 || {
        echo "[!] flock is required to drain configuration collection safely" >&2
        return 1
    }
    case "$wait_seconds" in
        ''|*[!0-9]*|0) return 1 ;;
    esac

    # get-configs.sh deliberately uses this one fixed native lock.  Do not
    # accept a caller-controlled pathname while uninstall is about to copy and
    # delete its published files.  /tmp is sticky on supported native hosts;
    # lstat + descriptor/path inode comparison below also rejects a substituted
    # symlink or a rename race.
    [[ -d /tmp && ! -L /tmp ]] || {
        echo "[!] Unsafe parent for config-collection lock: /tmp" >&2
        return 1
    }
    IFS=: read -r tmp_uid tmp_mode < <(stat -c '%u:%a' -- /tmp 2>/dev/null) || return 1
    if [[ "$tmp_uid" != "0" || ! "$tmp_mode" =~ ^[0-7]{3,4}$ ]] || \
       (( (8#$tmp_mode & 01000) == 0 )); then
        echo "[!] Config-collection lock parent is not a trusted sticky /tmp" >&2
        return 1
    fi
    if [[ ! -e "$lock_file" && ! -L "$lock_file" ]]; then
        # Publish a service-user-owned inode atomically. The uninstaller may be
        # run by root/an administrator; creating this path with shell redirection
        # would leave a 0600 lock that restored LLDPQ_USER cron jobs cannot open.
        # A prepared hard link appears at the public name only after ownership
        # and mode are final; EEXIST is a harmless get-configs creation race.
        if ! sudo python3 - "$lock_file" "$LLDPQ_USER" <<'PYTHON_CREATE_CONFIG_LOCK'
import os
import pwd
import sys
import tempfile

path, user = sys.argv[1:]
if path != "/tmp/lldpq-get-configs.lock":
    raise SystemExit("unexpected config-collection lock path")
account = pwd.getpwnam(user)
descriptor, temporary = tempfile.mkstemp(
    prefix=".lldpq-get-configs.lock.", dir="/tmp"
)
published = False
try:
    os.fchown(descriptor, account.pw_uid, account.pw_gid)
    os.fchmod(descriptor, 0o600)
    os.fsync(descriptor)
    os.close(descriptor)
    descriptor = -1
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError:
        pass
    else:
        published = True
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
if published:
    parent_fd = os.open(
        "/tmp", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
PYTHON_CREATE_CONFIG_LOCK
        then
            echo "[!] Could not create config-collection lock" >&2
            return 1
        fi
    fi
    [[ -f "$lock_file" && ! -L "$lock_file" ]] || {
        echo "[!] Refusing unsafe config-collection lock: $lock_file" >&2
        return 1
    }
    before_metadata=$(stat -c '%d:%i:%u:%h' -- "$lock_file" 2>/dev/null) || return 1
    expected_uid=$(id -u "$LLDPQ_USER" 2>/dev/null) || return 1
    IFS=: read -r _ _ lock_uid lock_links <<< "$before_metadata"
    if [[ "$lock_links" != "1" || "$lock_uid" != "$expected_uid" ]]; then
        echo "[!] Config-collection lock has unsafe ownership/link count" >&2
        return 1
    fi

    exec {UNINSTALL_CONFIG_COLLECTION_LOCK_FD}>>"$lock_file" || return 1
    after_metadata=$(stat -c '%d:%i:%u:%h' -- "$lock_file" 2>/dev/null || true)
    fd_metadata=$(stat -Lc '%d:%i:%u:%h' -- \
        "/proc/$$/fd/$UNINSTALL_CONFIG_COLLECTION_LOCK_FD" 2>/dev/null || true)
    if [[ -z "$after_metadata" || "$after_metadata" != "$before_metadata" || \
          "$fd_metadata" != "$before_metadata" ]]; then
        exec {UNINSTALL_CONFIG_COLLECTION_LOCK_FD}>&-
        UNINSTALL_CONFIG_COLLECTION_LOCK_FD=""
        echo "[!] Config-collection lock changed while it was opened" >&2
        return 1
    fi
    if ! flock -w "$wait_seconds" "$UNINSTALL_CONFIG_COLLECTION_LOCK_FD"; then
        exec {UNINSTALL_CONFIG_COLLECTION_LOCK_FD}>&-
        UNINSTALL_CONFIG_COLLECTION_LOCK_FD=""
        echo "[!] Timed out waiting for active configuration collection" >&2
        return 1
    fi
}

recover_interrupted_update_before_uninstall() {
    [[ -e "$LLDPQ_UPDATE_RECOVERY_MARKER" || \
       -L "$LLDPQ_UPDATE_RECOVERY_MARKER" ]] || return 0
    if $DRY_RUN; then
        echo "DRY-RUN  recover active interrupted LLDPq update before uninstall"
        return 0
    fi
    local helper_metadata
    helper_metadata=$(sudo stat -c '%u:%g:%a' -- \
        "$LLDPQ_UPDATE_RECOVERY_HELPER" 2>/dev/null || true)
    if [[ ! -f "$LLDPQ_UPDATE_RECOVERY_HELPER" || \
          -L "$LLDPQ_UPDATE_RECOVERY_HELPER" || \
          "$helper_metadata" != "0:0:755" ]]; then
        echo "[!] Active update recovery marker exists but its root-owned helper is unsafe or missing" >&2
        return 1
    fi
    sudo "$LLDPQ_UPDATE_RECOVERY_HELPER" || return 1
    if [[ -e "$LLDPQ_UPDATE_RECOVERY_MARKER" || \
          -L "$LLDPQ_UPDATE_RECOVERY_MARKER" ]]; then
        echo "[!] Interrupted update recovery did not clear its authority; uninstall stopped" >&2
        return 1
    fi
}

# Serialize against install.sh before reading mutable path configuration. A
# live update finishes first; a killed update leaves a durable authority that
# must be consumed before uninstall decides which tree is authoritative.
if ! acquire_uninstall_update_lock || \
   ! recover_interrupted_update_before_uninstall; then
    exit 1
fi

# ─── Detect install paths ─────────────────────────────────────────────
LLDPQ_INSTALL_DIR=""
LLDPQ_USER=""
LLDPQ_SRC=""
WEB_ROOT="/var/www/html"
ANSIBLE_DIR=""
EDITOR_ROOT=""
PROJECT_DIR=""

LLDPQ_CONFIG_FILE="${LLDPQ_CONFIG_FILE:-/etc/lldpq.conf}"
load_lldpq_uninstall_config "$LLDPQ_CONFIG_FILE"
LLDPQ_INSTALL_DIR="${LLDPQ_DIR:-}"
LLDPQ_USER="${LLDPQ_USER:-}"
LLDPQ_SOURCE_DIR="${LLDPQ_SRC:-}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

if [[ -z "$LLDPQ_INSTALL_DIR" ]]; then
    if [[ $EUID -eq 0 ]]; then
        LLDPQ_INSTALL_DIR="/opt/lldpq"
    else
        LLDPQ_INSTALL_DIR="$HOME/lldpq"
    fi
fi

[[ -z "$LLDPQ_USER" ]] && LLDPQ_USER="$(whoami)"

if [[ -L "$WEB_ROOT" || ( -e "$WEB_ROOT" && ! -d "$WEB_ROOT" ) ]]; then
    echo "Refusing unsafe symlink/non-directory WEB_ROOT: '$WEB_ROOT'" >&2
    exit 1
fi
LLDPQ_INSTALL_DIR=$(guard_destructive_path "LLDPq install" "$LLDPQ_INSTALL_DIR" 2) || exit 1
WEB_ROOT=$(guard_destructive_path "web root" "$WEB_ROOT" 2) || exit 1
LLDPQ_INSTALL_DIR=$(guard_recursive_target "LLDPq install" "$LLDPQ_INSTALL_DIR" false) || exit 1
WEB_ROOT=$(guard_recursive_target "web root" "$WEB_ROOT" true) || exit 1
if paths_overlap "$LLDPQ_INSTALL_DIR" "$WEB_ROOT"; then
    echo "Refusing uninstall: LLDPQ_DIR and WEB_ROOT overlap" >&2
    exit 1
fi
PARTIAL_INSTALL_TREE=false
if ! assert_lldpq_install_tree "$LLDPQ_INSTALL_DIR"; then
    PARTIAL_INSTALL_TREE=true
    if $FORCE_PARTIAL; then
        echo "  [!] --force-partial: the guarded partial install tree will be removed" >&2
    else
        echo "  [!] Known LLDPq system components will be cleaned, but this directory will be left in place." >&2
        echo "      Re-run with --force-partial only after verifying the path." >&2
    fi
fi
if $REMOVE_SOURCE && $PARTIAL_INSTALL_TREE && ! $FORCE_PARTIAL; then
    echo "Refusing --remove-source while the install tree is unrecognized/partial." >&2
    echo "Repair the installation or explicitly verify it with --force-partial first." >&2
    exit 1
fi
if [[ ! "$LLDPQ_USER" =~ ^[a-zA-Z0-9_][a-zA-Z0-9._-]*[$]?$ ]]; then
    echo "Refusing invalid LLDPQ_USER: '$LLDPQ_USER'" >&2
    exit 1
fi
LLDPQ_USER_HOME=$(getent passwd "$LLDPQ_USER" 2>/dev/null | cut -d: -f6)
if [[ -z "$LLDPQ_USER_HOME" || "$LLDPQ_USER_HOME" != /* || \
      "$LLDPQ_USER_HOME" == "/" || "$LLDPQ_USER_HOME" == *$'\n'* || \
      "$LLDPQ_USER_HOME" == *$'\r'* ]]; then
    echo "Refusing uninstall: could not resolve a safe home for $LLDPQ_USER" >&2
    exit 1
fi

# Keeping the source checkout is the default. Enforce that promise before any
# uninstall mutation: no recursively cleaned managed tree may contain the
# configured source, and the source may not contain one of those trees.
if [[ -n "$LLDPQ_SOURCE_DIR" ]]; then
    LLDPQ_SOURCE_DIR=$(guard_preserved_source_from_cleanup \
        "$LLDPQ_SOURCE_DIR" "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" \
        "$LLDPQ_USER_HOME/.lldpq-state") || exit 1
fi

LLDPQ_SOURCE_KIND=""
SOURCE_GIT_TRACKED_CHANGES=0
SOURCE_GIT_UNTRACKED=0
if $REMOVE_SOURCE; then
    if [[ -z "$LLDPQ_SOURCE_DIR" ]]; then
        echo "Refusing --remove-source: LLDPQ_SRC is not configured" >&2
        exit 1
    fi
    LLDPQ_SOURCE_KIND=$(source_provenance_operation validate \
        "$LLDPQ_SOURCE_DIR" "$LLDPQ_USER" "$LLDPQ_USER_HOME" \
        "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" "${ANSIBLE_DIR:-}" \
        "${EDITOR_ROOT:-}" "${PROJECT_DIR:-}") || exit 1
    inspect_source_git_state \
        "$LLDPQ_SOURCE_DIR" "$LLDPQ_USER" "$LLDPQ_SOURCE_KIND" || exit 1
fi

# ─── Banner ───────────────────────────────────────────────────────────
echo -e "${YELLOW}LLDPq Uninstall${NC}"
echo "================================================"
echo "Install dir:    $LLDPQ_INSTALL_DIR"
echo "Install user:   $LLDPQ_USER"
echo "Web root:       $WEB_ROOT"
echo "Dry run:        $DRY_RUN"
echo "Keep data:      $KEEP_DATA"
echo "Remove DHCP:    $REMOVE_DHCP"
echo "Remove nginx:   $REMOVE_NGINX_PKG"
echo "Remove docker:  $REMOVE_DOCKER_PKG"
if $REMOVE_SOURCE; then
    echo "Remove source:  true ($LLDPQ_SOURCE_DIR)"
    case "$LLDPQ_SOURCE_KIND" in
        git)
            echo "Source Git:     tracked changes=$SOURCE_GIT_TRACKED_CHANGES, untracked files=$SOURCE_GIT_UNTRACKED"
            ;;
        non-git)
            echo "Source Git:     non-Git/offline source (provenance verified)"
            ;;
        git-absent|non-git-absent)
            echo "Source state:   already absent (root-owned provenance verified)"
            ;;
    esac
else
    echo "Remove source:  false"
fi
echo "================================================"

if ! $AUTO_YES && ! $DRY_RUN; then
    echo -e "${RED}This will permanently remove LLDPq from this system.${NC}"
    read -p "Type 'UNINSTALL' to continue: " confirm
    if [[ "$confirm" != "UNINSTALL" ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# If keep-data staging fails, the live installation must remain recoverable.
# Snapshot only the two cron sources that are quiesced before the copy. Console,
# recovery units and privileged helpers are deliberately left untouched until
# the retained copy has committed.
QUIESCE_ROLLBACK_DIR=""
QUIESCE_HAD_CRONTAB=false
QUIESCE_HAD_CRON_D=false
FCGIWRAP_SERVICE_WAS_ACTIVE=false
FCGIWRAP_SOCKET_WAS_ACTIVE=false
KEEP_DATA_PREVIOUS_MOVED=false
KEEP_DATA_FRESH_PUBLISHED=false

valid_keep_data_snapshot() {
    local snapshot="${1:-}"
    [[ -n "$snapshot" && -d "$snapshot" && ! -L "$snapshot" && \
       -d "$snapshot/setup" && ! -L "$snapshot/setup" && \
       -d "$snapshot/runtime" && ! -L "$snapshot/runtime" && \
       -d "$snapshot/history" && ! -L "$snapshot/history" ]]
}

if $KEEP_DATA && ! $DRY_RUN; then
    QUIESCE_ROLLBACK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/lldpq-uninstall-quiesce-rollback.XXXXXX") || exit 1
    chmod 700 "$QUIESCE_ROLLBACK_DIR" || exit 1
    if [[ -f /etc/crontab ]]; then
        QUIESCE_HAD_CRONTAB=true
        sudo cp -a -- /etc/crontab "$QUIESCE_ROLLBACK_DIR/crontab" || {
            sudo rm -rf -- "$QUIESCE_ROLLBACK_DIR"
            echo "[!] Could not snapshot /etc/crontab before keep-data staging" >&2
            exit 1
        }
    fi
    if [[ -f /etc/cron.d/lldpq ]]; then
        QUIESCE_HAD_CRON_D=true
        sudo cp -a -- /etc/cron.d/lldpq "$QUIESCE_ROLLBACK_DIR/cron.d-lldpq" || {
            sudo rm -rf -- "$QUIESCE_ROLLBACK_DIR"
            echo "[!] Could not snapshot /etc/cron.d/lldpq before keep-data staging" >&2
            exit 1
        }
    fi
fi

rollback_keep_data_quiesce() {
    local failed=false
    if [[ "${KEEP_DATA_PREVIOUS_MOVED:-false}" == "true" ]]; then
        # Reconcile the two-rename retained-data transaction before deleting
        # its fresh stage. A signal may arrive after either mv but before the
        # following shell assignment, so filesystem state is authoritative:
        # an existing valid canonical snapshot is never overwritten; when the
        # canonical name is absent, restore the validated prior snapshot.
        if [[ -e "${KEEP_DATA_ROOT:-}" || -L "${KEEP_DATA_ROOT:-}" ]]; then
            if valid_keep_data_snapshot "$KEEP_DATA_ROOT"; then
                KEEP_DATA_FRESH_PUBLISHED=true
                if [[ -e "${KEEP_DATA_PREVIOUS:-}" || -L "${KEEP_DATA_PREVIOUS:-}" ]]; then
                    if valid_keep_data_snapshot "$KEEP_DATA_PREVIOUS"; then
                        sudo rm -rf -- "$KEEP_DATA_PREVIOUS" 2>/dev/null || failed=true
                    else
                        echo "[!] Prior retained-data transaction path is unsafe: $KEEP_DATA_PREVIOUS" >&2
                        failed=true
                    fi
                fi
                if ! $failed; then
                    KEEP_DATA_PREVIOUS_MOVED=false
                    KEEP_DATA_FRESH_PUBLISHED=false
                fi
            else
                echo "[!] Refusing to overwrite an unexpected canonical retained-data path" >&2
                failed=true
            fi
        elif valid_keep_data_snapshot "${KEEP_DATA_PREVIOUS:-}"; then
            if sudo mv -T -- "$KEEP_DATA_PREVIOUS" "$KEEP_DATA_ROOT"; then
                KEEP_DATA_PREVIOUS_MOVED=false
                KEEP_DATA_FRESH_PUBLISHED=false
            else
                echo "[!] Could not restore the prior retained-data snapshot" >&2
                failed=true
            fi
        else
            echo "[!] Prior retained-data snapshot is unavailable for transaction rollback" >&2
            failed=true
        fi
    fi
    if [[ -n "${KEEP_DATA_STAGE:-}" ]]; then
        sudo rm -rf -- "$KEEP_DATA_STAGE" 2>/dev/null || failed=true
    fi
    if [[ "${KEEP_DATA_PREVIOUS_MOVED:-false}" != "true" ]]; then
        KEEP_DATA_FRESH_PUBLISHED=false
    fi
    if [[ -n "$QUIESCE_ROLLBACK_DIR" ]]; then
        if $QUIESCE_HAD_CRONTAB; then
            sudo cp -a -- "$QUIESCE_ROLLBACK_DIR/crontab" /etc/crontab || failed=true
        fi
        if $QUIESCE_HAD_CRON_D; then
            sudo install -d -o root -g root -m 0755 /etc/cron.d || failed=true
            sudo cp -a -- "$QUIESCE_ROLLBACK_DIR/cron.d-lldpq" /etc/cron.d/lldpq || failed=true
        fi
    fi
    if $FCGIWRAP_SOCKET_WAS_ACTIVE; then
        sudo systemctl start fcgiwrap.socket 2>/dev/null || failed=true
    fi
    if $FCGIWRAP_SERVICE_WAS_ACTIVE; then
        sudo systemctl start fcgiwrap.service 2>/dev/null || failed=true
    fi
    [[ -z "$QUIESCE_ROLLBACK_DIR" ]] || sudo rm -rf -- "$QUIESCE_ROLLBACK_DIR" 2>/dev/null || true
    QUIESCE_ROLLBACK_DIR=""
    if $failed; then
        echo "[!] Writer rollback was incomplete; repair services before retrying" >&2
        return 1
    fi
    echo "  writer cron/CGI state restored"
}

# ─── 1. Stop running processes ────────────────────────────────────────
step "Stopping LLDPq processes..."
# Disable cron first so a once-per-minute Provision scheduler cannot recreate a
# detached worker between pkill and state removal. This is intentionally early
# and fail-closed; the later generic cron section remains idempotent.
if [[ -f /etc/crontab ]]; then
    if $DRY_RUN; then
        echo "DRY-RUN  disable LLDPq cron sources before worker quiesce"
    else
        _quiesce_cron_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-uninstall-quiesce.XXXXXX")
        filter_legacy_lldpq_crontab /etc/crontab "$_quiesce_cron_tmp" "$LLDPQ_INSTALL_DIR"
        if ! cmp -s /etc/crontab "$_quiesce_cron_tmp"; then
            if ! sudo install -o root -g root -m 644 \
                "$_quiesce_cron_tmp" /etc/crontab; then
                rm -f "$_quiesce_cron_tmp"
                echo "[!] Could not disable legacy LLDPq cron entries" >&2
                if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
                exit 1
            fi
        fi
        rm -f "$_quiesce_cron_tmp"
    fi
fi
if ! run "sudo rm -f /etc/cron.d/lldpq"; then
    echo "[!] Could not disable /etc/cron.d/lldpq" >&2
    if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
    exit 1
fi
if ! $DRY_RUN && [[ -e /etc/cron.d/lldpq ]]; then
    echo "[!] Provision scheduler cron source is still present" >&2
    if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
    exit 1
fi
if ! $DRY_RUN && [[ -f /etc/crontab ]]; then
    if grep -qE '/usr/local/bin/(lldpq|lldpq-trigger|lldpq-ai-analyze|lldpq-provision-scheduler|get-conf)([[:space:]]|$)' /etc/crontab || \
       grep -Fq -- "$LLDPQ_INSTALL_DIR/fabric-scan.sh" /etc/crontab || \
       grep -Fq -- "$LLDPQ_INSTALL_DIR/fabric-scan-cron.sh" /etc/crontab || \
       awk -v install_dir="$LLDPQ_INSTALL_DIR" '
           index($0, install_dir) > 0 &&
           $0 ~ /\.\/fabric-scan(-cron)?\.sh([[:space:]]|$)/ { found=1 }
           END { exit(found ? 0 : 1) }
       ' /etc/crontab; then
        echo "[!] An LLDPq scheduled writer remains in /etc/crontab" >&2
        if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
        exit 1
    fi
fi

for proc in lldpq-trigger lldpq-ai-analyze lldpq-provision-scheduler fabric-scan-cron.sh fabric-scan.sh collect-transceiver-fw.sh monitor.sh check-lldp.sh assets.sh; do
    if pgrep -f "/usr/local/bin/$proc" >/dev/null 2>&1 || \
       pgrep -f "$LLDPQ_INSTALL_DIR/$proc" >/dev/null 2>&1; then
        run "sudo pkill -f '$proc' 2>/dev/null || true"
        echo "  killed $proc"
    fi
done

quiesce_lldpq_writers() {
    local pattern pid remaining=false
    local -a patterns=(
        "lldpq-trigger"
        "lldpq-provision-scheduler"
        "provision-api.sh --discovery-worker"
        "provision-api.sh --discovery-schedule"
        "provision-api.sh --upgrade-worker"
        "provision-api.sh --upgrade-resume"
        "fabric-scan-cron.sh"
        "fabric-scan.sh"
        "lldpq-ai-analyze"
        "ai-api.sh"
        "collect-transceiver-fw.sh"
        "/usr/local/bin/lldpq([[:space:]]|$)"
        "monitor.sh"
        "check-lldp.sh"
        "assets.sh"
    )
    terminate_process_tree() {
        local parent="$1" child
        while IFS= read -r child; do
            [[ -n "$child" ]] && terminate_process_tree "$child"
        done < <(pgrep -P "$parent" 2>/dev/null || true)
        sudo kill -TERM "$parent" 2>/dev/null || true
        sleep 0.05
        if kill -0 "$parent" 2>/dev/null; then
            sudo kill -KILL "$parent" 2>/dev/null || true
        fi
    }
    for pattern in "${patterns[@]}"; do
        if $DRY_RUN; then
            run "sudo pkill -f -- '$pattern' 2>/dev/null || true"
            continue
        fi
        # Detached workers are shell session leaders whose Python/SSH children
        # no longer contain provision-api.sh in argv. Kill the captured tree
        # leaf-first so no orphan can write state after its parent disappears.
        while IFS= read -r pid; do
            [[ -n "$pid" && "$pid" != "$$" ]] && terminate_process_tree "$pid"
        done < <(pgrep -f -- "$pattern" 2>/dev/null || true)
    done
    $DRY_RUN && return 0
    for _attempt in {1..50}; do
        remaining=false
        for pattern in "${patterns[@]}"; do
            if pgrep -f -- "$pattern" >/dev/null 2>&1; then
                remaining=true
                break
            fi
        done
        $remaining || return 0
        sleep 0.1
    done
    echo "[!] LLDPq background writers did not quiesce" >&2
    return 1
}

if ! quiesce_lldpq_writers; then
    if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
    exit 1
fi

# get-configs.sh publishes and retires files in WEB_ROOT/configs and in its
# private config-collection namespace under this lock.  Drain any in-flight
# collection after disabling cron, then retain the descriptor until process
# exit so keep-data copying and both source deletions are one exclusive span.
if ! acquire_uninstall_config_collection_lock; then
    echo "[!] Configuration collection could not be drained; uninstall stopped" >&2
    if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
    exit 1
fi

# Close request creation before taking the retained copy.  Console and every
# recovery/helper authority still exist at this point, so a staging failure can
# restore the shared CGI service and exact cron snapshots without leaving a
# half-dismantled LLDPq installation.
systemctl is-active --quiet fcgiwrap.service 2>/dev/null && \
    FCGIWRAP_SERVICE_WAS_ACTIVE=true
systemctl is-active --quiet fcgiwrap.socket 2>/dev/null && \
    FCGIWRAP_SOCKET_WAS_ACTIVE=true
echo "  [i] fcgiwrap is shared: LLDPq CGI execution will be paused during cleanup."
echo "      Previously active units will be restored after the LLDPq route and CGI files are removed."
if ! run "sudo systemctl stop fcgiwrap.socket fcgiwrap.service 2>/dev/null"; then
    echo "[!] fcgiwrap could not be stopped safely" >&2
    if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
    exit 1
fi
if ! $DRY_RUN && \
   { systemctl is-active --quiet fcgiwrap.socket 2>/dev/null || \
     systemctl is-active --quiet fcgiwrap.service 2>/dev/null; }; then
    echo "[!] fcgiwrap could not be quiesced; no retained copy was taken" >&2
    if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
    exit 1
fi

# A CGI request could have launched a detached Provision worker while a cron
# tick could have launched fabric-scan-cron.sh during the
# short interval between the initial process pass and stopping the shared
# socket. With request creation now closed, make one final verified pass.
if ! quiesce_lldpq_writers; then
    echo "[!] LLDPq background writers are still active; retained data was not staged" >&2
    if $KEEP_DATA && ! $DRY_RUN; then rollback_keep_data_quiesce || true; fi
    exit 1
fi

# ─── Preserve explicitly selected operator data ──────────────────────
KEEP_DATA_ROOT="$LLDPQ_INSTALL_DIR/uninstall-kept-data"
KEEP_DATA_STAGE="$LLDPQ_INSTALL_DIR/.uninstall-kept-data.$$.staging"
KEEP_DATA_PREVIOUS="$LLDPQ_INSTALL_DIR/.uninstall-kept-data.$$.previous"

keep_data_abort() {
    $DRY_RUN || rollback_keep_data_quiesce || true
    echo "[!] Keep-data staging did not commit; the live install was not dismantled" >&2
    exit 1
}

preserve_keep_file() {
    local source="$1" destination="$2" label="$3"
    if [[ ! -e "$source" && ! -L "$source" ]]; then
        echo "  not present: $label"
        return 0
    fi
    if [[ -L "$source" || ! -f "$source" ]]; then
        echo "[!] Refusing unsafe keep-data file: $source" >&2
        return 1
    fi
    if ! run "sudo cp -a -- '$source' '$destination'"; then
        echo "[!] Could not preserve $label" >&2
        return 1
    fi
    echo "  kept $label"
}

preserve_keep_dir() {
    local source="$1" destination="$2" label="$3"
    if [[ ! -e "$source" && ! -L "$source" ]]; then
        echo "  not present: $label"
        return 0
    fi
    if [[ -L "$source" || ! -d "$source" ]]; then
        echo "[!] Refusing unsafe keep-data directory: $source" >&2
        return 1
    fi
    if ! run "sudo cp -a -- '$source' '$destination'"; then
        echo "[!] Could not preserve $label" >&2
        return 1
    fi
    echo "  kept $label"
}

if $KEEP_DATA; then
    step "Preserving selected Setup configuration and runtime data..."
    REPLACE_KEEP_DATA=false
    if [[ -e "$KEEP_DATA_ROOT" || -L "$KEEP_DATA_ROOT" ]]; then
        if valid_keep_data_snapshot "$KEEP_DATA_ROOT"; then
            REPLACE_KEEP_DATA=true
            echo "  [i] A prior retained-data snapshot exists; it will be replaced only after a fresh snapshot commits"
        else
            echo "[!] Existing keep-data path is not a valid committed retained-data directory" >&2
            keep_data_abort
        fi
    fi
    if [[ -e "$KEEP_DATA_STAGE" || -L "$KEEP_DATA_STAGE" || \
          -e "$KEEP_DATA_PREVIOUS" || -L "$KEEP_DATA_PREVIOUS" ]]; then
        echo "[!] Refusing an existing keep-data transaction path" >&2
        keep_data_abort
    fi

    run "sudo install -d -o '$LLDPQ_USER' -g www-data -m 0750 '$KEEP_DATA_STAGE' '$KEEP_DATA_STAGE/setup' '$KEEP_DATA_STAGE/runtime' '$KEEP_DATA_STAGE/history'" || keep_data_abort

    # The exact six Setup configuration files. Private SSH keys are excluded.
    preserve_keep_file "$LLDPQ_INSTALL_DIR/devices.yaml" \
        "$KEEP_DATA_STAGE/setup/devices.yaml" "devices.yaml" || keep_data_abort
    preserve_keep_file "$LLDPQ_INSTALL_DIR/tracking.yaml" \
        "$KEEP_DATA_STAGE/setup/tracking.yaml" "tracking.yaml" || keep_data_abort
    preserve_keep_file "$LLDPQ_INSTALL_DIR/notifications.yaml" \
        "$KEEP_DATA_STAGE/setup/notifications.yaml" "notifications.yaml" || keep_data_abort
    preserve_keep_file "$WEB_ROOT/topology.dot" \
        "$KEEP_DATA_STAGE/setup/topology.dot" "topology.dot" || keep_data_abort
    preserve_keep_file "$WEB_ROOT/topology_config.yaml" \
        "$KEEP_DATA_STAGE/setup/topology_config.yaml" "topology_config.yaml" || keep_data_abort
    preserve_keep_file "$WEB_ROOT/display-aliases.json" \
        "$KEEP_DATA_STAGE/setup/display-aliases.json" "display-aliases.json" || keep_data_abort
    preserve_keep_dir "$LLDPQ_INSTALL_DIR/monitor-results" \
        "$KEEP_DATA_STAGE/runtime/monitor-results" "monitor-results" || keep_data_abort
    preserve_keep_dir "$LLDPQ_INSTALL_DIR/lldp-results" \
        "$KEEP_DATA_STAGE/runtime/lldp-results" "lldp-results" || keep_data_abort
    preserve_keep_dir "$LLDPQ_INSTALL_DIR/alert-states" \
        "$KEEP_DATA_STAGE/runtime/alert-states" "alert-states" || keep_data_abort
    preserve_keep_dir "$WEB_ROOT/configs" \
        "$KEEP_DATA_STAGE/history/configs" "collected configs" || keep_data_abort
    preserve_keep_dir "$WEB_ROOT/hstr" \
        "$KEEP_DATA_STAGE/history/hstr" "command history" || keep_data_abort
    preserve_keep_dir "$WEB_ROOT/monitor-results" \
        "$KEEP_DATA_STAGE/history/web-monitor-results" "web monitoring history" || keep_data_abort

    # Never reuse stale retained data from an earlier uninstall/reinstall.  A
    # validated old snapshot remains at its original name until the fresh copy
    # is complete.  It is then moved aside, the fresh directory is atomically
    # published on the same filesystem, and the old snapshot is retired.  If
    # publication fails, restore the old name before aborting; current live data
    # has not been deleted at this point.
    if $DRY_RUN; then
        if $REPLACE_KEEP_DATA; then
            run "sudo mv -T -- '$KEEP_DATA_ROOT' '$KEEP_DATA_PREVIOUS'"
        fi
        run "sudo mv -T -- '$KEEP_DATA_STAGE' '$KEEP_DATA_ROOT'"
        if $REPLACE_KEEP_DATA; then
            run "sudo rm -rf -- '$KEEP_DATA_PREVIOUS'"
        fi
    else
        if $REPLACE_KEEP_DATA; then
            # Set intent before mv so EXIT reconciliation is safe even when a
            # signal lands after rename(2) but before the command returns.
            KEEP_DATA_PREVIOUS_MOVED=true
            if ! sudo mv -T -- "$KEEP_DATA_ROOT" "$KEEP_DATA_PREVIOUS"; then
                echo "[!] Could not reserve the existing retained-data snapshot" >&2
                keep_data_abort
            fi
        fi
        KEEP_DATA_FRESH_PUBLISHED=true
        if ! sudo mv -T -- "$KEEP_DATA_STAGE" "$KEEP_DATA_ROOT"; then
            KEEP_DATA_FRESH_PUBLISHED=false
            echo "[!] Could not publish the fresh retained-data snapshot" >&2
            if $REPLACE_KEEP_DATA && \
               sudo mv -T -- "$KEEP_DATA_PREVIOUS" "$KEEP_DATA_ROOT"; then
                KEEP_DATA_PREVIOUS_MOVED=false
            elif $REPLACE_KEEP_DATA; then
                echo "[!] The prior snapshot could not be restored from: $KEEP_DATA_PREVIOUS" >&2
            fi
            keep_data_abort
        fi
        if $REPLACE_KEEP_DATA && \
           ! sudo rm -rf -- "$KEEP_DATA_PREVIOUS"; then
            echo "[!] Fresh retained data committed, but the prior snapshot could not be retired" >&2
            keep_data_abort
        fi
        KEEP_DATA_PREVIOUS_MOVED=false
        KEEP_DATA_FRESH_PUBLISHED=false
    fi
    echo "  [i] Retained data committed at: $KEEP_DATA_ROOT"
fi

# The retained copy is committed. Its cron snapshots are no longer rollback
# authority and must not survive the uninstall.
if [[ -n "$QUIESCE_ROLLBACK_DIR" ]]; then
    sudo rm -rf -- "$QUIESCE_ROLLBACK_DIR" || {
        echo "[!] Could not retire the temporary quiesce rollback snapshot" >&2
        rollback_keep_data_quiesce || true
        exit 1
    }
    QUIESCE_ROLLBACK_DIR=""
fi

# Stop and remove the native Console bridge before its executable tree goes
# away. Keep every mutation behind run() so --dry-run remains side-effect free.
step "Removing Console service..."
run "sudo systemctl disable --now lldpq-console.service 2>/dev/null || true"
if ! $DRY_RUN && systemctl is-active --quiet lldpq-console.service 2>/dev/null; then
    echo "[!] Console service is still active; cleanup stopped" >&2
    exit 1
fi
if ! run "sudo rm -f '/etc/systemd/system/lldpq-console.service' '/etc/systemd/system/multi-user.target.wants/lldpq-console.service'"; then
    echo "[!] Could not remove Console service unit" >&2
    exit 1
fi
run "sudo systemctl daemon-reload 2>/dev/null || true"
echo "  Console service removed"
verify_absent "Console service unit" \
    /etc/systemd/system/lldpq-console.service \
    /etc/systemd/system/multi-user.target.wants/lldpq-console.service || true

# The shared update/collection lock is held for the entire uninstall, so no new
# update authority can appear after the preflight recovery check. Remove the
# boot guard only after verifying the marker is gone.
step "Removing interrupted-update recovery guard..."
if ! $DRY_RUN && \
   { [[ -e "$LLDPQ_UPDATE_RECOVERY_MARKER" ]] || \
     [[ -L "$LLDPQ_UPDATE_RECOVERY_MARKER" ]]; }; then
    echo "[!] Active update recovery authority remains; cleanup stopped" >&2
    exit 1
fi
run "sudo systemctl disable --now lldpq-update-recovery.service 2>/dev/null || true"
if ! $DRY_RUN && \
   systemctl is-active --quiet lldpq-update-recovery.service 2>/dev/null; then
    echo "[!] Interrupted-update recovery service is still active" >&2
    exit 1
fi
if ! run "sudo rm -f '$LLDPQ_UPDATE_RECOVERY_SERVICE' '/etc/systemd/system/multi-user.target.wants/lldpq-update-recovery.service' '$LLDPQ_UPDATE_RECOVERY_HELPER'"; then
    echo "[!] Could not remove interrupted-update recovery guard" >&2
    exit 1
fi
if ! run "sudo rm -rf '$LLDPQ_UPDATE_RECOVERY_STATE'"; then
    echo "[!] Could not remove inactive update recovery state" >&2
    exit 1
fi
run "sudo systemctl daemon-reload 2>/dev/null || true"
echo "  interrupted-update recovery guard removed"
verify_absent "Interrupted-update recovery authority" \
    "$LLDPQ_UPDATE_RECOVERY_SERVICE" "$LLDPQ_UPDATE_RECOVERY_HELPER" \
    "$LLDPQ_UPDATE_RECOVERY_STATE" || true

# Stop the watcher before removing either the lock or the executable tree. An
# authority published by an interrupted import must not start a now-orphaned
# recovery process while uninstall is in progress.
step "Removing retained-import recovery units..."
run "sudo systemctl disable --now lldpq-recovery.path lldpq-recovery.service 2>/dev/null || true"
if ! $DRY_RUN && \
   { sudo systemctl is-active --quiet lldpq-recovery.path 2>/dev/null || \
     sudo systemctl is-active --quiet lldpq-recovery.service 2>/dev/null; }; then
    echo "[!] Retained-import recovery units are still active; cleanup stopped" >&2
    exit 1
fi
for unit in lldpq-recovery.path lldpq-recovery.service; do
    if ! run "sudo rm -f '/etc/systemd/system/$unit' '/etc/systemd/system/multi-user.target.wants/$unit'"; then
        echo "[!] Could not remove retained-import recovery unit: $unit" >&2
        exit 1
    fi
done
run "sudo systemctl daemon-reload 2>/dev/null || true"
echo "  retained-import recovery service + path watcher removed"
verify_absent "Retained-import recovery unit" \
    /etc/systemd/system/lldpq-recovery.path \
    /etc/systemd/system/lldpq-recovery.service \
    /etc/systemd/system/multi-user.target.wants/lldpq-recovery.path \
    /etc/systemd/system/multi-user.target.wants/lldpq-recovery.service || true

# Purge only the helper's reserved, validated recovery directories. The helper
# resolves the passwd home, opens it and .lldpq-state with O_NOFOLLOW, validates
# ownership/modes/names, and deletes through directory file descriptors.
if $DRY_RUN; then
    echo "DRY-RUN  sudo '$LLDPQ_BACKUP_IMPORT_HELPER' purge-native-state --user '$LLDPQ_USER'"
else
    _backup_helper_metadata=$(sudo stat -c '%u:%g:%a' -- \
        "$LLDPQ_BACKUP_IMPORT_HELPER" 2>/dev/null || true)
    if [[ -f "$LLDPQ_BACKUP_IMPORT_HELPER" ]] && \
       [[ ! -L "$LLDPQ_BACKUP_IMPORT_HELPER" ]] && \
       [[ "$_backup_helper_metadata" == "0:0:755" ]]; then
        if ! sudo "$LLDPQ_BACKUP_IMPORT_HELPER" purge-native-state \
            --user "$LLDPQ_USER"; then
            echo "[!] Native backup-import recovery state was not safely removed; uninstall stopped" >&2
            exit 1
        fi
    elif native_recovery_namespace_present "$LLDPQ_USER"; then
        echo "[!] Recovery remnants exist but the root-owned cleanup helper is missing or unsafe" >&2
        echo "    Repair the installation before uninstalling so old snapshots cannot survive." >&2
        exit 1
    fi
fi
if [[ -d "$LLDPQ_BACKUP_IMPORT_HELPER" ]] && \
   [[ ! -L "$LLDPQ_BACKUP_IMPORT_HELPER" ]]; then
    echo "[!] Refusing to recursively remove unexpected helper directory: $LLDPQ_BACKUP_IMPORT_HELPER" >&2
    exit 1
fi
run "sudo rm -f '$LLDPQ_BACKUP_IMPORT_HELPER'"
if ! $DRY_RUN && \
   { [[ -e "$LLDPQ_BACKUP_IMPORT_HELPER" ]] || [[ -L "$LLDPQ_BACKUP_IMPORT_HELPER" ]]; }; then
    echo "[!] Root-owned backup/import helper could not be removed" >&2
    exit 1
fi
echo "  root-owned backup/import helper removed"

# ─── 2. Telemetry stack ───────────────────────────────────────────────
step "Removing telemetry stack..."
if [[ -f "$LLDPQ_INSTALL_DIR/telemetry/docker-compose.yaml" ]]; then
    TELEMETRY_REMOVED=false
    if $DRY_RUN; then
        echo "DRY-RUN  stop LLDPq telemetry compose project and remove its volumes"
        TELEMETRY_REMOVED=true
    elif command -v docker >/dev/null 2>&1 && \
         { (cd "$LLDPQ_INSTALL_DIR/telemetry" && docker compose down -v) || \
           (cd "$LLDPQ_INSTALL_DIR/telemetry" && sudo docker compose down -v); }; then
        TELEMETRY_REMOVED=true
    elif command -v docker-compose >/dev/null 2>&1 && \
         { (cd "$LLDPQ_INSTALL_DIR/telemetry" && docker-compose down -v) || \
           (cd "$LLDPQ_INSTALL_DIR/telemetry" && sudo docker-compose down -v); }; then
        TELEMETRY_REMOVED=true
    fi
    if $TELEMETRY_REMOVED; then
        echo "  telemetry containers + volumes removed"
    else
        record_cleanup_failure "Telemetry compose project/volumes could not be removed"
    fi
fi

# ─── Optional source checkout pre-commit ─────────────────────────────
# Revalidate after all writers and request entry points are quiesced, but defer
# the irreversible deletion until every ordinary cleanup step has succeeded.
# The runtime config, provenance and web/lifecycle authority therefore remain
# available if validation or any later ordinary cleanup reports a problem.
step "Validating LLDPq source checkout..."
if $REMOVE_SOURCE; then
    _source_kind_now=$(source_provenance_operation validate \
        "$LLDPQ_SOURCE_DIR" "$LLDPQ_USER" "$LLDPQ_USER_HOME" \
        "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" "${ANSIBLE_DIR:-}" \
        "${EDITOR_ROOT:-}" "${PROJECT_DIR:-}") || {
        echo "[!] LLDPQ_SRC failed its final provenance check; config/provenance retained" >&2
        exit 1
    }
    inspect_source_git_state \
        "$LLDPQ_SOURCE_DIR" "$LLDPQ_USER" "$_source_kind_now" || {
        echo "[!] LLDPQ_SRC Git state failed its final safety check; config/provenance retained" >&2
        exit 1
    }
    LLDPQ_SOURCE_KIND="$_source_kind_now"
    case "$LLDPQ_SOURCE_KIND" in
        git)
            echo "  source checkout validated; late removal will include tracked changes=$SOURCE_GIT_TRACKED_CHANGES, untracked files=$SOURCE_GIT_UNTRACKED"
            ;;
        non-git)
            echo "  verified non-Git/offline source; late removal will include its complete tree"
            ;;
        git-absent|non-git-absent)
            echo "  provenance-bound source is already absent; late commit is idempotent"
            ;;
    esac
else
    echo "  source checkout kept (use --remove-source for provenance-bound removal)"
fi

# ─── 3. Cron jobs ─────────────────────────────────────────────────────
step "Removing LLDPq cron jobs..."
if [[ -f /etc/crontab ]]; then
    if $DRY_RUN; then
        echo "DRY-RUN  remove only legacy LLDPq command paths from /etc/crontab"
    else
        _legacy_cron_tmp=$(mktemp "${TMPDIR:-/tmp}/lldpq-uninstall-cron.XXXXXX")
        filter_legacy_lldpq_crontab /etc/crontab "$_legacy_cron_tmp" "$LLDPQ_INSTALL_DIR"
        if ! cmp -s /etc/crontab "$_legacy_cron_tmp"; then
            sudo install -o root -g root -m 644 "$_legacy_cron_tmp" /etc/crontab || \
                record_cleanup_failure "Legacy LLDPq crontab entries could not be removed"
        fi
        rm -f "$_legacy_cron_tmp"
    fi
    echo "  legacy LLDPq entries removed from /etc/crontab"
fi
if [[ -f /etc/cron.d/lldpq ]]; then
    run_required "Provision cron source could not be removed" \
        "sudo rm -f /etc/cron.d/lldpq" && echo "  /etc/cron.d/lldpq removed"
fi
if ! $DRY_RUN && [[ -f /etc/crontab ]] && \
   grep -qE '/usr/local/bin/(lldpq|lldpq-trigger|lldpq-ai-analyze|lldpq-provision-scheduler|get-conf)([[:space:]]|$)' /etc/crontab; then
    record_cleanup_failure "Legacy LLDPq entries remain in /etc/crontab"
fi
verify_absent "Provision cron source" /etc/cron.d/lldpq || true

# ─── 4. Bin scripts ───────────────────────────────────────────────────
step "Removing CLI tools..."
BIN_TOOLS=(lldpq lldpq-config lldpq-trigger lldpq-ai-analyze lldpq-provision-scheduler zzh pping send-cmd get-conf netprobe-ai)
for bin in "${BIN_TOOLS[@]}"; do
    if [[ -e "/usr/local/bin/$bin" || -L "/usr/local/bin/$bin" ]]; then
        run_required "CLI tool could not be removed: /usr/local/bin/$bin" \
            "sudo rm -f '/usr/local/bin/$bin'" && echo "  removed /usr/local/bin/$bin"
    fi
done
for bin in "${BIN_TOOLS[@]}"; do
    verify_absent "CLI tool" "/usr/local/bin/$bin" || true
done

# ─── 5. Sudoers ───────────────────────────────────────────────────────
step "Removing sudoers files..."
for f in www-data-lldpq www-data-provision; do
    if [[ -e "/etc/sudoers.d/$f" || -L "/etc/sudoers.d/$f" ]]; then
        run_required "Sudoers policy could not be removed: /etc/sudoers.d/$f" \
            "sudo rm -f '/etc/sudoers.d/$f'" && echo "  removed /etc/sudoers.d/$f"
    fi
done
verify_absent "LLDPq sudoers policy" \
    /etc/sudoers.d/www-data-lldpq /etc/sudoers.d/www-data-provision || true

# ─── 6. Auth + sessions + config ──────────────────────────────────────
step "Removing config + auth files..."
for f in \
    /etc/lldpq.conf.lock /etc/lldpq-users.conf \
    /etc/lldpq.conf.lldpq-root-stage /etc/crontab.lldpq-root-stage \
    /etc/cron.d/lldpq.lldpq-root-stage \
    /etc/dhcp/dhcpd.conf.lldpq-root-stage \
    /etc/dhcp/dhcpd.hosts.lldpq-root-stage \
    /etc/dhcp/dhcpd.host.lldpq-root-stage \
    /etc/default/isc-dhcp-server.lldpq-root-stage \
    /etc/rsyslog.d/10-lldpq-dhcp.conf; do
    if [[ -e "$f" || -L "$f" ]]; then
        run_required "Config/auth file could not be removed: $f" \
            "sudo rm -f '$f'" && echo "  removed $f"
    fi
done
if $PARTIAL_INSTALL_TREE && ! $FORCE_PARTIAL; then
    echo "  kept /etc/lldpq.conf so a verified --force-partial rerun retains the custom paths"
else
    echo "  retained /etc/lldpq.conf until the final uninstall commit"
fi
if systemctl is-active --quiet rsyslog 2>/dev/null && \
   ! run "sudo systemctl restart rsyslog"; then
    record_cleanup_failure "rsyslog could not be restarted after removing LLDPq routing"
fi
if ! remove_native_lldpq_fixed_tree "$LLDPQ_USER" /var/log/lldpq; then
    record_cleanup_failure "Dedicated LLDPq log tree could not be removed safely"
elif $DRY_RUN; then
    echo "  /var/log/lldpq is safe to remove"
else
    echo "  removed /var/log/lldpq"
fi
verify_absent "Dedicated LLDPq log tree" /var/log/lldpq || true
if [[ -e /var/lib/lldpq || -L /var/lib/lldpq ]]; then
    if remove_native_lldpq_fixed_tree "$LLDPQ_USER" /var/lib/lldpq; then
        if $DRY_RUN; then
            echo "  /var/lib/lldpq is safe to remove"
        else
            echo "  removed /var/lib/lldpq"
        fi
    else
        record_cleanup_failure "Private LLDPq state could not be removed safely"
    fi
fi
verify_absent "LLDPq auth/lock/staging" \
    /etc/lldpq.conf.lock /etc/lldpq-users.conf \
    /etc/lldpq.conf.lldpq-root-stage /etc/crontab.lldpq-root-stage \
    /etc/cron.d/lldpq.lldpq-root-stage \
    /etc/dhcp/dhcpd.conf.lldpq-root-stage \
    /etc/dhcp/dhcpd.hosts.lldpq-root-stage \
    /etc/dhcp/dhcpd.host.lldpq-root-stage \
    /etc/default/isc-dhcp-server.lldpq-root-stage \
    /etc/rsyslog.d/10-lldpq-dhcp.conf || true
verify_absent "Private LLDPq state" /var/lib/lldpq || true

# ─── 7. nginx site ────────────────────────────────────────────────────
step "Removing nginx site..."
if [[ -L /etc/nginx/sites-enabled/lldpq ]] || [[ -f /etc/nginx/sites-enabled/lldpq ]]; then
    run_required "Enabled nginx LLDPq site could not be removed" \
        "sudo rm -f /etc/nginx/sites-enabled/lldpq" && echo "  removed sites-enabled/lldpq"
fi
if [[ -e /etc/nginx/sites-available/lldpq || -L /etc/nginx/sites-available/lldpq ]]; then
    run_required "Available nginx LLDPq site could not be removed" \
        "sudo rm -f /etc/nginx/sites-available/lldpq" && echo "  removed sites-available/lldpq"
fi
if command -v nginx >/dev/null 2>&1; then
    if ! run "sudo nginx -t >/dev/null 2>&1"; then
        record_cleanup_failure "nginx validation failed after removing the LLDPq site"
    elif systemctl is-active --quiet nginx 2>/dev/null && \
         ! run "sudo systemctl reload nginx"; then
        record_cleanup_failure "nginx reload failed after removing the LLDPq site"
    fi
fi
verify_absent "nginx LLDPq site" \
    /etc/nginx/sites-enabled/lldpq /etc/nginx/sites-available/lldpq || true

# ─── 8. Web content ───────────────────────────────────────────────────
step "Removing web content under $WEB_ROOT..."
WEB_ROOT_CLEANABLE=false
if [[ ! -e "$WEB_ROOT" && ! -L "$WEB_ROOT" ]]; then
    echo "  web root is absent; its child artifacts are already clean"
elif [[ -L "$WEB_ROOT" || ! -d "$WEB_ROOT" ]]; then
    record_cleanup_failure "Refused unexpected symlink/non-directory web root: $WEB_ROOT"
else
    WEB_ROOT_CLEANABLE=true
fi
WEB_TARGETS=(
    "$WEB_ROOT/index.html" "$WEB_ROOT/login.html" "$WEB_ROOT/start.html"
    "$WEB_ROOT/setup.html" "$WEB_ROOT/commands.html" "$WEB_ROOT/console.html"
    "$WEB_ROOT/assets.html" "$WEB_ROOT/device.html" "$WEB_ROOT/configs.html"
    "$WEB_ROOT/lldp.html" "$WEB_ROOT/lldp-problem.html" "$WEB_ROOT/archive.html"
    "$WEB_ROOT/dev-conf.html" "$WEB_ROOT/edit-config.sh" "$WEB_ROOT/edit-devices.sh"
    "$WEB_ROOT/edit-topology.sh" "$WEB_ROOT/editor-test.html"
    "$WEB_ROOT/fabric-api.sh" "$WEB_ROOT/fabric-config.html" "$WEB_ROOT/fabric-deploy.html"
    "$WEB_ROOT/fabric-editor.html" "$WEB_ROOT/fabric-exit.html"
    "$WEB_ROOT/auth-api.sh" "$WEB_ROOT/auth-guard.sh" "$WEB_ROOT/ansible-api.sh"
    "$WEB_ROOT/ai-api.sh" "$WEB_ROOT/ai.html" "$WEB_ROOT/ai_command_policy.py"
    "$WEB_ROOT/ai_insights.py" "$WEB_ROOT/ai_context.py"
    "$WEB_ROOT/assets-api.sh" "$WEB_ROOT/setup_safety.py"
    "$WEB_ROOT/provision.html" "$WEB_ROOT/provision-api.sh" "$WEB_ROOT/admin-page.sh" \
    "$WEB_ROOT/lifecycle-scope.js"
    "$WEB_ROOT/handover.html" "$WEB_ROOT/tracking-api.sh"
    "$WEB_ROOT/search.html" "$WEB_ROOT/search-api.sh"
    "$WEB_ROOT/setup-api.sh" "$WEB_ROOT/telemetry.html"
    "$WEB_ROOT/tracepath.html" "$WEB_ROOT/transceiver.html"
    "$WEB_ROOT/vlan-report.html" "$WEB_ROOT/vrf-report.html"
    "$WEB_ROOT/lldpq-ztp-new-device-flow.html"
    "$WEB_ROOT/trigger-assets.sh" "$WEB_ROOT/trigger-configs.sh"
    "$WEB_ROOT/trigger-lldp.sh" "$WEB_ROOT/trigger-monitor.sh"
    "$WEB_ROOT/trigger-transceiver.sh" "$WEB_ROOT/p2p-alias.js"
    "$WEB_ROOT/cumulus-ztp.sh" "$WEB_ROOT/serial-mapping.txt"
    "$WEB_ROOT/topology.dot" "$WEB_ROOT/topology_config.yaml"
    "$WEB_ROOT/display-aliases.json"
    "$WEB_ROOT/topology.dot.bak" "$WEB_ROOT/topology.dot.lock"
    "$WEB_ROOT/topology_config.yaml.bak" "$WEB_ROOT/topology_config.yaml.lock"
    "$WEB_ROOT/display-aliases.json.bak" "$WEB_ROOT/display-aliases.json.lock"
    "$WEB_ROOT/VERSION"
    "$WEB_ROOT/device-cache.json" "$WEB_ROOT/fabric-scan-cache.json"
    "$WEB_ROOT/discovery-cache.json" "$WEB_ROOT/inventory.json"
    "$WEB_ROOT/assets.ini" "$WEB_ROOT/lldp_results.ini"
    "$WEB_ROOT/problems-lldp_results.ini"
    "$WEB_ROOT/ai-analysis.json" "$WEB_ROOT/ai-learnings.json"
    "$WEB_ROOT/ai-analysis-snapshot.json"
    "$WEB_ROOT/.inventory.lock" "$WEB_ROOT/.dhcp-operation.lock"
)
WEB_DIRS=(
    "$WEB_ROOT/css" "$WEB_ROOT/png" "$WEB_ROOT/topology"
    "$WEB_ROOT/configs" "$WEB_ROOT/hstr" "$WEB_ROOT/monitor-results"
    "$WEB_ROOT/generated_config_folder" "$WEB_ROOT/provision-uploads" "$WEB_ROOT/monaco"
)

if $WEB_ROOT_CLEANABLE; then
    remove_managed_provision_root_artifacts
    for f in "${WEB_TARGETS[@]}"; do
        if [[ -e "$f" || -L "$f" ]]; then
            run_required "Web artifact could not be removed: $f" \
                "sudo rm -f '$f'" && echo "  removed $f"
        fi
    done
    # Atomic Setup/Provision editors and the assets publisher can leave a
    # hidden same-directory stage only if killed between creation and
    # replace/cleanup. Match exact managed basenames and suffixes only; a
    # symlink with one of these reserved names is safe to unlink but never
    # followed.
    run_required "Atomic web staging artifacts could not be removed" "sudo find -P '$WEB_ROOT' -mindepth 1 -maxdepth 1 \
        \( -type f -o -type l \) \
        \( -name '.topology.dot.*' -o -name '.topology_config.yaml.*' \
           -o -name '.display-aliases.json.*' \
           -o -name '.inventory.json.*.tmp' \
           -o -name '.discovery-cache.json.*.tmp' \
           -o -name '.cumulus-ztp.sh.*.tmp' \
           -o -name '.serial-mapping.txt.*.tmp' \
           -o -name '.assets.ini.tmp.*' \
           -o -name '.device-cache.json.tmp.*' \
           -o -name '.assets.ini.rollback.*' \
           -o -name '.device-cache.json.rollback.*' \) -delete" || true

    if ! remove_managed_web_runtime_residue "$LLDPQ_USER" "$WEB_ROOT"; then
        record_cleanup_failure "Managed support downloads/monitor stages could not be removed safely"
    fi
    for d in "${WEB_DIRS[@]}"; do
        # Selected history was copied outside WEB_ROOT above. Never leave it in
        # a directory that another/default nginx virtual host might expose.
        if [[ -e "$d" || -L "$d" ]]; then
            run_required "Web directory could not be removed: $d" \
                "sudo rm -rf '$d'" && echo "  removed $d"
        fi
    done
    verify_absent "LLDPq web artifact" "${WEB_TARGETS[@]}" || true
    verify_absent "LLDPq web directory" "${WEB_DIRS[@]}" || true
    verify_managed_provision_root_artifacts_absent
    if ! $DRY_RUN && sudo find -P "$WEB_ROOT" -mindepth 1 -maxdepth 1 \
        \( -name '.topology.dot.*' -o -name '.topology_config.yaml.*' \
           -o -name '.display-aliases.json.*' \
           -o -name '.inventory.json.*.tmp' \
           -o -name '.discovery-cache.json.*.tmp' \
           -o -name '.cumulus-ztp.sh.*.tmp' \
           -o -name '.serial-mapping.txt.*.tmp' \
           -o -name '.assets.ini.tmp.*' \
           -o -name '.device-cache.json.tmp.*' \
           -o -name '.assets.ini.rollback.*' \
           -o -name '.device-cache.json.rollback.*' \
           -o -name '.monitor-results.new.*' \) -print -quit | grep -q .; then
        record_cleanup_failure "Atomic web staging residue remains under $WEB_ROOT"
    fi
fi

# The LLDPq nginx route and CGI files are now gone, so reactivating a shared
# fcgiwrap unit cannot enqueue another backup import. Restore only what was
# active before uninstall; --remove-nginx intentionally leaves it stopped for
# the package-removal phase below.
if $REMOVE_NGINX_PKG; then
    echo "  fcgiwrap remains stopped because --remove-nginx was requested"
elif $FCGIWRAP_SOCKET_WAS_ACTIVE || $FCGIWRAP_SERVICE_WAS_ACTIVE; then
    step "Restoring shared fcgiwrap service..."
    if $FCGIWRAP_SOCKET_WAS_ACTIVE; then
        run "sudo systemctl start fcgiwrap.socket"
    fi
    if $FCGIWRAP_SERVICE_WAS_ACTIVE; then
        run "sudo systemctl start fcgiwrap.service"
    fi
    FCGIWRAP_RESTORE_FAILED=false
    if ! $DRY_RUN; then
        if $FCGIWRAP_SOCKET_WAS_ACTIVE && \
           ! systemctl is-active --quiet fcgiwrap.socket 2>/dev/null; then
            FCGIWRAP_RESTORE_FAILED=true
        fi
        if $FCGIWRAP_SERVICE_WAS_ACTIVE && \
           ! systemctl is-active --quiet fcgiwrap.service 2>/dev/null; then
            FCGIWRAP_RESTORE_FAILED=true
        fi
    fi
    if $FCGIWRAP_RESTORE_FAILED; then
        echo "[!] LLDPq was removed, but the previously active shared fcgiwrap unit could not be restored" >&2
        echo "    Restore it manually with: sudo systemctl start fcgiwrap.socket fcgiwrap.service" >&2
        exit 1
    fi
    echo "  shared fcgiwrap state restored"
fi

# ─── 9. Install directory ─────────────────────────────────────────────
step "Removing install directory..."
if [[ -d "$LLDPQ_INSTALL_DIR" ]]; then
    if $PARTIAL_INSTALL_TREE && ! $FORCE_PARTIAL; then
        echo "  left unrecognized partial directory in place: $LLDPQ_INSTALL_DIR"
    elif $KEEP_DATA; then
        # All retained files were copied into this single non-web directory.
        # Delete the live application tree and its former writable locations.
        run_required "Live install tree could not be removed around retained data" \
            "find '$LLDPQ_INSTALL_DIR' -mindepth 1 -maxdepth 1 ! -name 'uninstall-kept-data' -exec sudo rm -rf -- {} +" || true
        echo "  cleaned $LLDPQ_INSTALL_DIR (selected data kept in uninstall-kept-data/)"
    else
        run_required "LLDPq install directory could not be removed" \
            "sudo rm -rf '$LLDPQ_INSTALL_DIR'" && echo "  removed $LLDPQ_INSTALL_DIR"
    fi
fi
if ! $DRY_RUN && { ! $PARTIAL_INSTALL_TREE || $FORCE_PARTIAL; } && $KEEP_DATA; then
    if [[ ! -d "$KEEP_DATA_ROOT" || -L "$KEEP_DATA_ROOT" ]] || \
       find "$LLDPQ_INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name 'uninstall-kept-data' -print -quit | grep -q .; then
        record_cleanup_failure "Install-tree residue remains outside uninstall-kept-data"
    fi
elif ! $DRY_RUN && { ! $PARTIAL_INSTALL_TREE || $FORCE_PARTIAL; } && \
     [[ -e "$LLDPQ_INSTALL_DIR" || -L "$LLDPQ_INSTALL_DIR" ]]; then
    record_cleanup_failure "LLDPq install directory remains: $LLDPQ_INSTALL_DIR"
fi

# ─── 10. DHCP config (LLDPq markers only) ────────────────────────────
step "Cleaning DHCP markers..."
if $REMOVE_DHCP; then
    if systemctl is-active --quiet isc-dhcp-server 2>/dev/null; then
        run_required "isc-dhcp-server could not be stopped" \
            "sudo systemctl stop isc-dhcp-server" || true
    fi
    if systemctl is-enabled --quiet isc-dhcp-server 2>/dev/null; then
        run_required "isc-dhcp-server could not be disabled" \
            "sudo systemctl disable isc-dhcp-server" || true
    fi
    for f in /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.hosts /etc/default/isc-dhcp-server /var/lib/dhcp/dhcpd.leases; do
        if [[ -e "$f" || -L "$f" ]]; then
            run_required "Requested DHCP data could not be removed: $f" \
                "sudo rm -f '$f'" && echo "  removed $f"
        fi
    done
    run_required "isc-dhcp-server package purge failed" \
        "sudo apt-get remove -y --purge isc-dhcp-server >/dev/null 2>&1" || true
    verify_absent "Requested DHCP data" \
        /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.hosts \
        /etc/default/isc-dhcp-server /var/lib/dhcp/dhcpd.leases || true
    if ! $DRY_RUN && package_is_installed isc-dhcp-server; then
        record_cleanup_failure "isc-dhcp-server remains installed after requested purge"
    fi
else
    echo "  --remove-dhcp not set, leaving DHCP service config alone"
fi

# ─── 11. Group membership cleanup ─────────────────────────────────────
step "Cleaning group memberships..."
if id www-data >/dev/null 2>&1; then
    run "sudo gpasswd -d www-data '$LLDPQ_USER' 2>/dev/null || true"
    run "sudo gpasswd -d '$LLDPQ_USER' www-data 2>/dev/null || true"
    echo "  removed group cross-membership"
fi

# ─── 12. Optional package removal ─────────────────────────────────────
if $REMOVE_NGINX_PKG; then
    step "Removing nginx + fcgiwrap packages..."
    for unit in nginx fcgiwrap; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            run_required "$unit could not be stopped before package purge" \
                "sudo systemctl stop '$unit'" || true
        fi
    done
    NGINX_PACKAGE_CANDIDATES=(nginx nginx-common nginx-core nginx-full nginx-light fcgiwrap)
    NGINX_PACKAGES=()
    for package in "${NGINX_PACKAGE_CANDIDATES[@]}"; do
        package_is_installed "$package" && NGINX_PACKAGES+=("$package")
    done
    if ((${#NGINX_PACKAGES[@]})); then
        run_required "nginx/fcgiwrap package purge failed" \
            "sudo apt-get remove -y --purge ${NGINX_PACKAGES[*]} >/dev/null 2>&1" || true
    fi
    if ! $DRY_RUN; then
        for package in "${NGINX_PACKAGE_CANDIDATES[@]}"; do
            package_is_installed "$package" && \
                record_cleanup_failure "$package remains installed after requested purge"
        done
    fi
fi

if $REMOVE_DOCKER_PKG; then
    step "Removing Docker packages..."
    if systemctl is-active --quiet docker 2>/dev/null; then
        run_required "docker service could not be stopped before package purge" \
            "sudo systemctl stop docker" || true
    fi
    DOCKER_PACKAGE_CANDIDATES=(docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin docker.io docker-compose containerd runc)
    DOCKER_PACKAGES=()
    for package in "${DOCKER_PACKAGE_CANDIDATES[@]}"; do
        package_is_installed "$package" && DOCKER_PACKAGES+=("$package")
    done
    if ((${#DOCKER_PACKAGES[@]})); then
        run_required "Docker package purge failed" \
            "sudo apt-get remove -y --purge ${DOCKER_PACKAGES[*]} >/dev/null 2>&1" || true
    fi
    run_required "Docker engine/containerd data could not be removed" \
        "sudo rm -rf /var/lib/docker /var/lib/containerd" || true
    verify_absent "Requested Docker data" /var/lib/docker /var/lib/containerd || true
    if ! $DRY_RUN; then
        for package in "${DOCKER_PACKAGE_CANDIDATES[@]}"; do
            package_is_installed "$package" && \
                record_cleanup_failure "$package remains installed after requested purge"
        done
    fi
fi

# ─── 13. Private lifecycle state ──────────────────────────────────────
step "Removing LLDPq Ansible CGI temporary state..."
for _ansible_temp_root in \
    /tmp/ansible-www /tmp/ansible-tmp /tmp/ansible-cache; do
    if [[ -e "$_ansible_temp_root" || -L "$_ansible_temp_root" ]]; then
        if remove_native_lldpq_fixed_tree "$LLDPQ_USER" "$_ansible_temp_root"; then
            if $DRY_RUN; then
                echo "  $_ansible_temp_root is safe to remove"
            else
                echo "  removed $_ansible_temp_root"
            fi
        else
            record_cleanup_failure "LLDPq Ansible CGI temp tree could not be removed safely: $_ansible_temp_root"
        fi
    fi
done
verify_absent "LLDPq Ansible CGI temporary state" \
    /tmp/ansible-www /tmp/ansible-tmp /tmp/ansible-cache || true
unset _ansible_temp_root

# This is a dedicated LLDPq namespace. Its complete tree is validated and
# removed without following symlinks or crossing a filesystem boundary.
step "Removing old LLDPq lifecycle state..."
LLDPQ_USER_STATE="$LLDPQ_USER_HOME/.lldpq-state"
if [[ -e "$LLDPQ_USER_STATE" || -L "$LLDPQ_USER_STATE" ]]; then
    if remove_native_lldpq_state "$LLDPQ_USER"; then
        if $DRY_RUN; then
            echo "  dedicated .lldpq-state tree is safe to remove"
        else
            echo "  dedicated .lldpq-state tree removed"
        fi
    else
        record_cleanup_failure "Dedicated .lldpq-state tree could not be removed safely"
    fi
fi
verify_absent "Private LLDPq lifecycle state" "$LLDPQ_USER_STATE" || true

# The collectors are stopped, cron/API/CLI entry points are gone and both lock
# descriptors remain held by this shell. It is now safe to unlink their fixed
# public names; no new LLDPq worker can split onto a replacement lock inode.
step "Removing fixed LLDPq temporary state..."
if remove_fixed_lldpq_temp_files "$LLDPQ_USER" defer-monitor; then
    if $DRY_RUN; then
        echo "  fixed LLDPq temp locks/log fallback are safe to remove"
    else
        echo "  fixed LLDPq temp locks/log fallback removed (update lock held for final commit)"
    fi
else
    record_cleanup_failure "Fixed LLDPq temporary artifacts could not be removed safely"
fi
verify_absent "Fixed LLDPq temporary artifact" \
    /tmp/lldpq-get-configs.lock /tmp/lldpq-fabric-scan.lock \
    /tmp/lldpq-trigger-daemon.lock \
    /tmp/lldpq-console-audit.log /tmp/ansible-gitconfig \
    /tmp/.monitor_web_trigger /tmp/.configs_web_trigger \
    /tmp/.transceiver_web_trigger /tmp/.assets_refresh_trigger \
    /tmp/lldp_trigger_daemon.pid /tmp/configs_running.lock \
    /tmp/fabric-scan.log || true

# ─── 14. Final destructive commit ─────────────────────────────────────
# No optional source tree is touched while an ordinary cleanup failure exists.
# Keep /etc/lldpq.conf, source provenance and the installed lifecycle authority
# until this point so a selected-source validation/removal failure is repairable
# and a retry has the exact same root-owned deletion authority.
if $UNINSTALL_INCOMPLETE; then
    echo "[!] Final uninstall commit was not attempted; runtime config, source provenance and lifecycle authority were retained." >&2
    report_cleanup_failures
    exit 1
fi

if $PARTIAL_INSTALL_TREE && ! $FORCE_PARTIAL; then
    step "Retaining partial-install recovery authority..."
    echo "  kept /etc/lldpq.conf and $LLDPQ_SOURCE_PROVENANCE"
    echo "  use --force-partial after manually verifying the retained install tree"
else
    # Reject impossible authority shapes before the optional source commit. A
    # symlink is safe to unlink as a link; a directory at either fixed file path
    # is not silently removed.
    if [[ -d /etc/lldpq.conf && ! -L /etc/lldpq.conf ]]; then
        record_cleanup_failure "Refused unexpected configuration directory: /etc/lldpq.conf"
    fi
    if [[ -d "$LLDPQ_SOURCE_PROVENANCE" && ! -L "$LLDPQ_SOURCE_PROVENANCE" ]]; then
        record_cleanup_failure "Refused unexpected source-provenance directory: $LLDPQ_SOURCE_PROVENANCE"
    fi
    if $UNINSTALL_INCOMPLETE; then
        echo "[!] Final uninstall commit was not attempted; runtime config, source provenance and lifecycle authority were retained." >&2
        report_cleanup_failures
        exit 1
    fi

    step "Committing optional LLDPq source removal..."
    if $REMOVE_SOURCE; then
        _source_kind_now=$(source_provenance_operation validate \
            "$LLDPQ_SOURCE_DIR" "$LLDPQ_USER" "$LLDPQ_USER_HOME" \
            "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" "${ANSIBLE_DIR:-}" \
            "${EDITOR_ROOT:-}" "${PROJECT_DIR:-}") || {
            echo "[!] LLDPQ_SRC failed its commit-time provenance check; config/provenance/lifecycle retained" >&2
            exit 1
        }
        inspect_source_git_state \
            "$LLDPQ_SOURCE_DIR" "$LLDPQ_USER" "$_source_kind_now" || {
            echo "[!] LLDPQ_SRC Git state failed its commit-time safety check; config/provenance/lifecycle retained" >&2
            exit 1
        }
        if $DRY_RUN; then
            if [[ "$_source_kind_now" == *-absent ]]; then
                echo "DRY-RUN  provenance-bound LLDPQ_SRC is already absent: $LLDPQ_SOURCE_DIR"
            else
                echo "DRY-RUN  remove provenance-bound LLDPQ_SRC: $LLDPQ_SOURCE_DIR"
                if [[ "$_source_kind_now" == "git" ]]; then
                    echo "DRY-RUN  Git summary: tracked changes=$SOURCE_GIT_TRACKED_CHANGES, untracked files=$SOURCE_GIT_UNTRACKED"
                else
                    echo "DRY-RUN  source is a verified non-Git/offline checkout"
                fi
            fi
        elif [[ "$_source_kind_now" == *-absent ]]; then
            if [[ -e "$LLDPQ_SOURCE_DIR" || -L "$LLDPQ_SOURCE_DIR" ]]; then
                echo "[!] LLDPQ_SRC reappeared after its absence check; config/provenance/lifecycle retained" >&2
                exit 1
            fi
            echo "  provenance-bound LLDPQ_SRC is already absent: $LLDPQ_SOURCE_DIR"
        else
            cd / || {
                echo "[!] Could not leave the source working directory; config/provenance/lifecycle retained" >&2
                exit 1
            }
            if ! _removed_source_kind=$(source_provenance_operation remove \
                "$LLDPQ_SOURCE_DIR" "$LLDPQ_USER" "$LLDPQ_USER_HOME" \
                "$LLDPQ_INSTALL_DIR" "$WEB_ROOT" "${ANSIBLE_DIR:-}" \
                "${EDITOR_ROOT:-}" "${PROJECT_DIR:-}"); then
                echo "[!] LLDPQ_SRC removal failed; config/provenance/lifecycle retained for inspection" >&2
                exit 1
            fi
            if [[ -e "$LLDPQ_SOURCE_DIR" || -L "$LLDPQ_SOURCE_DIR" ]]; then
                echo "[!] LLDPQ_SRC remains after guarded removal; config/provenance/lifecycle retained" >&2
                exit 1
            fi
            echo "  removed provenance-bound LLDPQ_SRC: $LLDPQ_SOURCE_DIR"
        fi
    else
        echo "  source checkout kept by request"
    fi
fi

# ─── 15. Web uninstall authority ──────────────────────────────────────
# Keep this authority through every ordinary cleanup and the optional source
# commit. The running shell already has the root-owned uninstaller open, so its
# final fixed config/provenance retirement can continue after the installed copy
# is removed; the still-public monitor lock serializes that short final window.
step "Removing uninstall web authority..."
if $DRY_RUN; then
    echo "DRY-RUN  hold $LLDPQ_LIFECYCLE_LOCK and remove the matching marker, web authority and lifecycle lock"
else
    if ! sudo -n /usr/bin/flock -x "$LLDPQ_LIFECYCLE_LOCK" \
        /bin/bash -s -- "$LLDPQ_UNINSTALL_JOB_ID" <<'ROOT_UNINSTALL_CLEANUP'
set -u
expected_job_id="$1"
marker=/run/lldpq-uninstall.active
sudoers=/etc/sudoers.d/www-data-lldpq-uninstall
run_dir=/run/lldpq-uninstall
gateway=/usr/local/libexec/lldpq-uninstall-web.py
uninstaller=/usr/local/libexec/lldpq-uninstall.sh
lifecycle=/etc/lldpq.lifecycle.lock

if [[ -e "$marker" || -L "$marker" ]]; then
    [[ -f "$marker" && ! -L "$marker" ]] || exit 82
    metadata=$(stat -c '%u:%g:%a:%h:%s' -- "$marker" 2>/dev/null || true)
    marker_job_id=$(cat -- "$marker" 2>/dev/null || true)
    [[ -n "$expected_job_id" && "$expected_job_id" =~ ^[a-f0-9]{32}$ ]] || exit 81
    [[ "$metadata" == "0:0:644:1:33" && "$marker_job_id" == "$expected_job_id" ]] || exit 82
elif [[ -n "$expected_job_id" ]]; then
    exit 84
fi

rm -f -- "$sudoers" || exit 85
rm -rf -- "$run_dir" || exit 86
rm -f -- "$gateway" || exit 87
rm -f -- "$uninstaller" || exit 88
rm -f -- "$lifecycle" || exit 89

for path in "$sudoers" "$run_dir" "$gateway" "$uninstaller" "$lifecycle"; do
    [[ ! -e "$path" && ! -L "$path" ]] || exit 90
done

# The public marker is the fail-closed authority seen by both Setup and a new
# installer.  Keep it present while the private active record/run directory is
# retired and until every other authority removal above has succeeded.  A
# partial cleanup therefore remains visibly "uninstall active" instead of
# allowing concurrent lifecycle work against a half-removed installation.
if [[ -e "$marker" || -L "$marker" ]]; then
    rm -f -- "$marker" || exit 83
fi
[[ ! -e "$marker" && ! -L "$marker" ]] || exit 91
ROOT_UNINSTALL_CLEANUP
    then
        record_cleanup_failure "Could not atomically remove the uninstall lifecycle/web authority"
    fi
fi
if ! $DRY_RUN && {
    [[ -e "$LLDPQ_UNINSTALL_ACTIVE_MARKER" || -L "$LLDPQ_UNINSTALL_ACTIVE_MARKER" ]] ||
    [[ -e "$LLDPQ_UNINSTALL_SUDOERS" || -L "$LLDPQ_UNINSTALL_SUDOERS" ]] ||
    [[ -e "$LLDPQ_UNINSTALL_RUN_DIR" || -L "$LLDPQ_UNINSTALL_RUN_DIR" ]] ||
    [[ -e "$LLDPQ_UNINSTALL_GATEWAY" || -L "$LLDPQ_UNINSTALL_GATEWAY" ]] ||
    [[ -e "$LLDPQ_UNINSTALL_HELPER" || -L "$LLDPQ_UNINSTALL_HELPER" ]] ||
    [[ -e "$LLDPQ_LIFECYCLE_LOCK" || -L "$LLDPQ_LIFECYCLE_LOCK" ]]
}; then
    echo "[!] Residual uninstall web authority remains; uninstall cannot be reported successful" >&2
    exit 1
fi
echo "  uninstall gateway, confirmation tokens and installed helper removed"

if $UNINSTALL_INCOMPLETE; then
    echo "[!] Runtime config and source provenance were retained because lifecycle cleanup did not commit." >&2
    report_cleanup_failures
    exit 1
fi

# The public monitor-lock pathname was deliberately kept while its descriptor
# remained exclusively locked. Thus a concurrent installer/update cannot enter
# after the lifecycle marker is retired but before these final fixed authorities
# are removed. A web-authority failure above leaves both config and provenance
# intact, so the same source-removal request remains diagnosable/retryable.
if ! $PARTIAL_INSTALL_TREE || $FORCE_PARTIAL; then
    step "Removing final LLDPq configuration authority..."
    if [[ -e /etc/lldpq.conf || -L /etc/lldpq.conf ]]; then
        if ! run_required "LLDPq configuration could not be removed" \
            "sudo rm -f '/etc/lldpq.conf'"; then
            report_cleanup_failures
            exit 1
        fi
        if $DRY_RUN; then
            echo "  /etc/lldpq.conf would be removed at final commit"
        else
            echo "  removed /etc/lldpq.conf"
        fi
    fi
    verify_absent "LLDPq configuration" /etc/lldpq.conf || true
    if $UNINSTALL_INCOMPLETE; then
        report_cleanup_failures
        exit 1
    fi

    step "Removing source provenance..."
    if [[ -e "$LLDPQ_SOURCE_PROVENANCE" || -L "$LLDPQ_SOURCE_PROVENANCE" ]]; then
        if ! run_required "Source provenance could not be removed" \
            "sudo rm -f '$LLDPQ_SOURCE_PROVENANCE'"; then
            report_cleanup_failures
            exit 1
        fi
        if $DRY_RUN; then
            echo "  source provenance would be removed at final commit"
        else
            echo "  source provenance removed"
        fi
    fi
    verify_absent "Source provenance" "$LLDPQ_SOURCE_PROVENANCE" || true
    if $UNINSTALL_INCOMPLETE; then
        report_cleanup_failures
        exit 1
    fi
fi

# Retire the public lock name only after all source/config/provenance commits.
# The held descriptor remains locked until this shell exits, while no LLDPq
# lifecycle authority or mutable configuration remains for a new worker to use.
step "Removing final LLDPq update lock..."
if remove_fixed_lldpq_temp_files "$LLDPQ_USER" monitor-only; then
    if $DRY_RUN; then
        echo "  fixed LLDPq update lock is safe to remove at final commit"
    else
        echo "  fixed LLDPq update lock removed"
    fi
else
    record_cleanup_failure "Fixed LLDPq update lock could not be removed safely"
fi
verify_absent "Fixed LLDPq update lock" /tmp/lldpq-monitor.lock || true

if $UNINSTALL_INCOMPLETE; then
    report_cleanup_failures
    exit 1
fi

# ─── Done ─────────────────────────────────────────────────────────────
echo ""
if $DRY_RUN; then
    echo -e "${YELLOW}Dry run complete. No changes were made.${NC}"
else
    echo -e "${GREEN}LLDPq has been uninstalled.${NC}"
fi
echo ""
echo "Verify with:"
if $PARTIAL_INSTALL_TREE && ! $FORCE_PARTIAL; then
    echo "  ls /etc/lldpq* 2>/dev/null   # config + source provenance are intentionally retained"
    echo "  inspect $LLDPQ_INSTALL_DIR manually (partial tree intentionally retained)"
elif $KEEP_DATA; then
    echo "  ls /etc/lldpq* 2>/dev/null   # should be empty"
    echo "  find '$KEEP_DATA_ROOT' -maxdepth 3 -print  # retained data only"
else
    echo "  ls /etc/lldpq* 2>/dev/null   # should be empty"
    echo "  ls $LLDPQ_INSTALL_DIR 2>/dev/null  # should not exist"
fi
echo "  systemctl status nginx       # nginx state (if you kept it)"
echo "  crontab -l; cat /etc/crontab # no LLDPq lines"
