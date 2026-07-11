#!/usr/bin/env bash
# ansible-api.sh - Ansible Config Editor API
# Called by nginx fcgiwrap
#
# Actions:
#   - list: List all editable files (host_vars, group_vars, playbooks)
#   - read: Read a specific file
#   - write: Write to a specific file
#   - diff: Run ansible diff playbook
#   - deploy: Run ansible deploy playbook

# Admin-only guard (validates session, exits 401/403 if not admin)
source "$(dirname "$0")/auth-guard.sh"
require_admin

# Load config with fallback
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
LLDPQ_DIR="${LLDPQ_DIR:-$HOME/lldpq}"

# EDITOR_ROOT: directory shown in Fabric Editor (falls back to ANSIBLE_DIR)
EDITOR_ROOT="${EDITOR_ROOT:-$ANSIBLE_DIR}"

# If neither EDITOR_ROOT nor ANSIBLE_DIR is usable, bail out
if { [[ "$EDITOR_ROOT" == "NoNe" ]] || [[ -z "$EDITOR_ROOT" ]]; } && \
   { [[ "$ANSIBLE_DIR" == "NoNe" ]] || [[ -z "$ANSIBLE_DIR" ]]; }; then
    echo "Content-Type: application/json"
    echo ""
    echo '{"success": false, "error": "Ansible not configured"}'
    exit 0
fi

# Normalize: if EDITOR_ROOT is NoNe but ANSIBLE_DIR is set, use ANSIBLE_DIR
[[ "$EDITOR_ROOT" == "NoNe" || -z "$EDITOR_ROOT" ]] && EDITOR_ROOT="$ANSIBLE_DIR"

# Setup ansible environment for www-data user
export ANSIBLE_HOME="/tmp/ansible-www"
export HOME="$ANSIBLE_HOME"
export ANSIBLE_LOCAL_TEMP="/tmp/ansible-tmp"
export ANSIBLE_CACHE_PLUGIN_CONNECTION="/tmp/ansible-cache"
mkdir -p "$ANSIBLE_HOME" "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_CACHE_PLUGIN_CONNECTION" 2>/dev/null || true
chmod 775 "$ANSIBLE_HOME" "$ANSIBLE_LOCAL_TEMP" "$ANSIBLE_CACHE_PLUGIN_CONNECTION" 2>/dev/null || true

# Fix git directory permissions after git operations
fix_git_permissions() {
    if [ -d "$ANSIBLE_DIR/.git" ]; then
        # Get the original owner of the ansible directory
        local owner=$(stat -c '%U' "$ANSIBLE_DIR" 2>/dev/null || stat -f '%Su' "$ANSIBLE_DIR" 2>/dev/null)
        # Fix ownership: owner:www-data with group write
        sudo -n chown -R "$owner:www-data" "$ANSIBLE_DIR/.git" 2>/dev/null || true
        sudo -n chmod -R g+rwX "$ANSIBLE_DIR/.git" 2>/dev/null || true
    fi
}

# Parse query string
parse_query() {
    local query="$QUERY_STRING"
    # Extract action
    ACTION=$(echo "$query" | sed -n 's/.*action=\([^&]*\).*/\1/p')
    # Extract file parameter
    FILE=$(echo "$query" | sed -n 's/.*file=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
    # Extract host parameter and URL-decode it
    HOST=$(echo "$query" | sed -n 's/.*host=\([^&]*\).*/\1/p')
    # URL decode (handle %2C for comma, etc.)
    HOST=$(echo "$HOST" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
}

# Output JSON response
json_response() {
    echo "Content-Type: application/json"
    echo "Access-Control-Allow-Origin: *"
    echo ""
    echo "$1"
}

# Security: validate file path is within allowed directories
validate_path() {
    local file="$1"
    local realpath=$(realpath -m "$EDITOR_ROOT/$file" 2>/dev/null)
    local editor_realpath=$(realpath "$EDITOR_ROOT" 2>/dev/null)
    
    # Check if path is within editor root directory
    if [[ "$realpath" != "$editor_realpath"* ]]; then
        return 1
    fi
    
    # Block dangerous/binary file types
    if [[ "$file" =~ \.(pyc|so|exe|dll|bin|class)$ ]]; then
        return 1
    fi
    
    # Block system files
    if [[ "$file" =~ ^\.git/ ]] || [[ "$file" =~ ^\.vscode/ ]] || [[ "$file" =~ ^\.crossnote/ ]] || [[ "$file" =~ __pycache__/ ]]; then
        return 1
    fi
    
    return 0
}

# List editable files
list_files() {
    # Find all files quickly using find with optimized options (no cache for fresh results)
    local files_json=""
    if [ -d "$EDITOR_ROOT" ]; then
        files_json=$(find "$EDITOR_ROOT" -type f \
            ! -path "*/.git/*" \
            ! -path "*/.vscode/*" \
            ! -path "*/.crossnote/*" \
            ! -path "*/__pycache__/*" \
            ! -path "*/.ansible/*" \
            ! -path "*/.ssh/*" \
            ! -path "*/.cache/*" \
            ! -path "*/.local/*" \
            ! -name "*.pyc" \
            ! -name "*.swp" \
            ! -name "*.bak" \
            ! -name "*~" \
            ! -name ".bash_history" \
            ! -name ".sudo_as_admin_successful" \
            ! -name ".wget-hsts" \
            2>/dev/null | sed "s|^$EDITOR_ROOT/||" | sort | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
    else
        files_json="[]"
    fi
    
    # Get groups from inventory file (fallback: inventory.ini -> hosts)
    local groups=()
    local inventory_file=""
    if [ -f "$ANSIBLE_DIR/inventory/inventory.ini" ]; then
        inventory_file="$ANSIBLE_DIR/inventory/inventory.ini"
    elif [ -f "$ANSIBLE_DIR/inventory/hosts" ]; then
        inventory_file="$ANSIBLE_DIR/inventory/hosts"
    fi
    
    if [ -n "$inventory_file" ]; then
        while IFS= read -r line; do
            # Skip comments and empty lines
            if [[ "$line" =~ ^[[:space:]]*# ]] || [[ "$line" =~ ^[[:space:]]*$ ]]; then
                continue
            fi
            
            # Group header [groupname]
            if [[ "$line" =~ ^\[([^]]+)\] ]]; then
                current_group="${BASH_REMATCH[1]}"
                groups+=("$current_group")
            fi
        done < "$inventory_file"
    fi
    
    # Get individual hosts from host_vars directory
    local hosts=()
    if [ -d "$ANSIBLE_DIR/inventory/host_vars" ]; then
        while IFS= read -r -d '' file; do
            # Extract hostname from filename (without extension)
            local hostname=$(basename "$file")
            hostname="${hostname%.yaml}"
            hostname="${hostname%.yml}"
            hosts+=("$hostname")
        done < <(find "$ANSIBLE_DIR/inventory/host_vars" -maxdepth 1 -type f \( -name "*.yaml" -o -name "*.yml" \) -print0 2>/dev/null)
    fi
    
    # Build JSON for groups and hosts (files_json already built above with caching)
    local groups_json=$(printf '%s\n' "${groups[@]}" | sort -u | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
    local hosts_json=$(printf '%s\n' "${hosts[@]}" | sort -u | python3 -c 'import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
    
    local is_docker="false"
    [ -f "/.dockerenv" ] && is_docker="true"
    
    json_response "{\"success\": true, \"files\": $files_json, \"groups\": $groups_json, \"hosts\": $hosts_json, \"is_docker\": $is_docker}"
}

# Read file
read_file() {
    local file="$1"
    
    if ! validate_path "$file"; then
        json_response '{"success": false, "error": "Invalid file path"}'
        return
    fi
    
    local full_path="$EDITOR_ROOT/$file"
    
    if [ ! -f "$full_path" ]; then
        json_response '{"success": false, "error": "File not found"}'
        return
    fi
    
    local content=$(cat "$full_path" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    json_response "{\"success\": true, \"content\": $content}"
}

# Write file
write_file() {
    local file="$1"
    
    if ! validate_path "$file"; then
        json_response '{"success": false, "error": "Invalid file path"}'
        return
    fi
    
    local full_path="$EDITOR_ROOT/$file"
    
    # Read POST data
    local post_data
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        post_data=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
    else
        post_data=$(cat)
    fi
    
    # Extract content from JSON
    local content=$(echo "$post_data" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get("content", ""))
except:
    print("")
' 2>/dev/null)

    # Check content parameter is present (empty content is a valid save)
    local has_content=$(echo "$post_data" | python3 -c '
import sys, json
try:
    data = json.load(sys.stdin)
    print("yes" if "content" in data else "no")
except:
    print("no")
' 2>/dev/null)

    if [ "$has_content" != "yes" ]; then
        json_response '{"success": false, "error": "No content provided"}'
        return
    fi
    
    # Write new content
    echo "$content" > "$full_path"
    
    if [ $? -eq 0 ]; then
        json_response '{"success": true, "message": "File saved successfully"}'
    else
        json_response '{"success": false, "error": "Failed to write file"}'
    fi
}

# Delete file
delete_file() {
    local file="$1"
    
    if ! validate_path "$file"; then
        json_response '{"success": false, "error": "Invalid file path"}'
        return
    fi
    
    local full_path="$EDITOR_ROOT/$file"
    
    if [ ! -f "$full_path" ]; then
        json_response '{"success": false, "error": "File not found"}'
        return
    fi
    
    rm -f "$full_path" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        json_response '{"success": true}'
    else
        json_response '{"success": false, "error": "Failed to delete file"}'
    fi
}

# Run ansible diff
run_diff() {
    local host="$1"
    
    if [ -z "$host" ]; then
        json_response '{"success": false, "error": "No host specified"}'
        return
    fi
    
    # Sanitize host name
    host=$(echo "$host" | tr -cd '[:alnum:]-_,.')
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Run diff playbook (include localhost for summary play)
    local output
    output=$(ANSIBLE_FORCE_COLOR=true ansible-playbook playbooks/diff_switch_configs.yaml -l "$host,localhost" 2>&1)
    local exit_code=$?
    
    # Escape output for JSON
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    # Exit codes: 0=success, 2=unreachable (but we continue with ignore_unreachable)
    # Treat both as success since playbook completes for reachable hosts
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Diff failed with exit code $exit_code\"}"
    fi
}

# Run ansible deploy
run_deploy() {
    local host="$1"
    
    if [ -z "$host" ]; then
        json_response '{"success": false, "error": "No host specified"}'
        return
    fi
    
    # Sanitize host name
    host=$(echo "$host" | tr -cd '[:alnum:]-_,.')
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Run deploy playbook (include localhost for summary play)
    local output
    output=$(ANSIBLE_FORCE_COLOR=true ansible-playbook playbooks/deploy_switch_configs.yaml -l "$host,localhost" 2>&1)
    local exit_code=$?
    
    # Escape output for JSON
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    # Exit codes: 0=success, 2=unreachable (but we continue with ignore_unreachable)
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 2 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Deploy failed with exit code $exit_code\"}"
    fi
}

# Run ansible generate configs
run_generate() {
    local host="$1"
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Run generate playbook
    local output
    if [ -n "$host" ] && [ "$host" != "all" ]; then
        # Sanitize host name (include localhost for summary play)
        host=$(echo "$host" | tr -cd '[:alnum:]-_,.')
        output=$(ANSIBLE_FORCE_COLOR=true ansible-playbook playbooks/generate_switch_nvue_yaml_configs.yaml -l "$host,localhost" 2>&1)
    else
        output=$(ANSIBLE_FORCE_COLOR=true ansible-playbook playbooks/generate_switch_nvue_yaml_configs.yaml 2>&1)
    fi
    local exit_code=$?
    
    # Escape output for JSON
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    if [ $exit_code -eq 0 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Generate failed with exit code $exit_code\"}"
    fi
}

# Git functions
git_commit_push() {
    local message="$1"
    
    if [ -z "$message" ]; then
        json_response '{"success": false, "error": "No commit message provided"}'
        return
    fi
    
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    # Fix ownership and add safe directory
    export HOME="$ANSIBLE_HOME"
    git config --global user.email "ansible-editor@lldpq.local" 2>/dev/null || true
    git config --global user.name "Ansible Editor" 2>/dev/null || true
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    # Stage all changes
    git add -A 2>&1
    
    # Check if there are changes to commit
    if git diff --cached --quiet; then
        json_response '{"success": true, "output": "Nothing to commit - working tree clean"}'
        return
    fi
    
    # Commit and push
    local output
    output=$(git commit -m "$message" 2>&1)
    local commit_code=$?
    
    if [ $commit_code -eq 0 ]; then
        # Fix git permissions after commit
        fix_git_permissions
        
        # Try to push
        local push_output
        push_output=$(git push 2>&1)
        local push_code=$?
        output="$output\n$push_output"
        
        # Fix git permissions after push
        fix_git_permissions
        
        if [ $push_code -eq 0 ]; then
            local output_json=$(echo -e "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
            json_response "{\"success\": true, \"output\": $output_json}"
        else
            local output_json=$(echo -e "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
            json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Push failed\"}"
        fi
    else
        local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Commit failed\"}"
    fi
}

git_pull() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    output=$(git pull 2>&1)
    local exit_code=$?
    
    # Fix git permissions after pull
    fix_git_permissions
    
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    if [ $exit_code -eq 0 ]; then
        json_response "{\"success\": true, \"output\": $output_json}"
    else
        json_response "{\"success\": false, \"output\": $output_json, \"error\": \"Git pull failed\"}"
    fi
}

git_status() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    output=$(git status 2>&1)
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    json_response "{\"success\": true, \"output\": $output_json}"
}

git_log() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    # Pretty format with fixed widths: hash | date | relative time | author | message
    output=$(git --no-pager log --graph --decorate=no --date=format:'%Y-%m-%d %H:%M' --pretty=format:'%<(8,trunc)%h │ %<(16)%ad │ %<(14)%cr │ %<(12,trunc)%an │ %s' -n 30 2>&1)
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    json_response "{\"success\": true, \"output\": $output_json}"
}

git_diff() {
    cd "$ANSIBLE_DIR" || {
        json_response '{"success": false, "error": "Cannot access ansible directory"}'
        return
    }
    
    export GIT_CONFIG_GLOBAL=/tmp/ansible-gitconfig
    git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
    
    local output
    output=$(git diff 2>&1)
    local output_json=$(echo "$output" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')
    
    json_response "{\"success\": true, \"output\": $output_json}"
}

# Main
parse_query

# Get commit message from POST data if present
if [ "$ACTION" = "git-commit" ]; then
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
        MESSAGE=$(echo "$POST_DATA" | sed -n 's/.*message=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
    fi
fi

case "$ACTION" in
    list)
        list_files
        ;;
    read)
        read_file "$FILE"
        ;;
    write)
        write_file "$FILE"
        ;;
    delete)
        delete_file "$FILE"
        ;;
    generate)
        run_generate "$HOST"
        ;;
    diff)
        run_diff "$HOST"
        ;;
    deploy)
        run_deploy "$HOST"
        ;;
    git-commit)
        git_commit_push "$MESSAGE"
        ;;
    git-pull)
        git_pull
        ;;
    git-status)
        git_status
        ;;
    git-log)
        git_log
        ;;
    git-diff)
        git_diff
        ;;
    git-reset)
        cd "$ANSIBLE_DIR" || { json_response '{"success": false, "error": "Cannot access ansible directory"}'; exit 0; }
        git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
        
        # Reset all changes (discard uncommitted changes)
        output=$(git checkout . 2>&1)
        reset_code=$?
        
        # Fix git permissions after reset
        fix_git_permissions
        
        if [ $reset_code -eq 0 ]; then
            json_response '{"success": true, "output": "All uncommitted changes have been discarded."}'
        else
            json_response "{\"success\": false, \"error\": \"Failed to reset: $output\"}"
        fi
        ;;
    git-reset-file)
        # Reset single file to last commit
        FILE=$(echo "$QUERY_STRING" | sed -n 's/.*file=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        
        if [ -z "$FILE" ]; then
            json_response '{"success": false, "error": "No file specified"}'
            exit 0
        fi
        
        cd "$ANSIBLE_DIR" || { json_response '{"success": false, "error": "Cannot access ansible directory"}'; exit 0; }
        git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
        
        # Check if file exists in git
        if ! git ls-files --error-unmatch "$FILE" >/dev/null 2>&1; then
            # File not tracked, check if it's a new file
            if [ -f "$FILE" ]; then
                json_response '{"success": false, "error": "File is not tracked by git (new file)"}'
            else
                json_response '{"success": false, "error": "File not found"}'
            fi
            exit 0
        fi
        
        # Reset single file
        output=$(git checkout HEAD -- "$FILE" 2>&1)
        reset_code=$?
        
        # Fix git permissions after reset
        fix_git_permissions
        
        if [ $reset_code -eq 0 ]; then
            json_response '{"success": true, "output": "File reset to last commit."}'
        else
            json_response "{\"success\": false, \"error\": \"Failed to reset file: $output\"}"
        fi
        ;;
    grep)
        # Search in specified path (default: inventory) - like mgrep
        QUERY=$(echo "$QUERY_STRING" | sed -n 's/.*query=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        SEARCH_PATH=$(echo "$QUERY_STRING" | sed -n 's/.*path=\([^&]*\).*/\1/p')
        SEARCH_PATH="${SEARCH_PATH:-inventory}"
        
        if [ -z "$QUERY" ]; then
            json_response '{"success": false, "error": "No search query provided"}'
            exit 0
        fi
        
        cd "$EDITOR_ROOT" || { json_response '{"success": false, "error": "Cannot access editor directory"}'; exit 0; }
        
        # Run grep like mgrep and properly preserve ANSI escape sequences via Python
        export GREP_QUERY="$QUERY"
        export GREP_PATH="$SEARCH_PATH"
        
        # Output headers first (like json_response does)
        echo "Content-Type: application/json"
        echo "Access-Control-Allow-Origin: *"
        echo ""
        
        python3 << 'PYEOF'
import subprocess
import json
import os

query = os.environ.get('GREP_QUERY', '')
path = os.environ.get('GREP_PATH', 'inventory')

result = subprocess.run(
    ['grep', '-rnIi', '--color=always', query, path],
    capture_output=True,
    text=True
)
output = result.stdout
# Limit to 100 lines
lines = output.split('\n')[:100]
output = '\n'.join(lines)
print(json.dumps({'success': True, 'output': output}))
PYEOF
        ;;
    get-modified-devices)
        # Get list of modified device hostnames from git diff
        cd "$ANSIBLE_DIR" || { json_response '{"success": false, "error": "Cannot access ansible directory"}'; exit 0; }
        git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
        
        # Get modified files in inventory/host_vars/
        modified_files=$(git diff --name-only 2>/dev/null | grep "inventory/host_vars/.*\.yaml$" || true)
        untracked_files=$(git ls-files --others --exclude-standard 2>/dev/null | grep "inventory/host_vars/.*\.yaml$" || true)
        
        # Combine, extract hostnames, make unique
        all_hostnames=$(echo -e "${modified_files}\n${untracked_files}" | grep -v "^$" | xargs -I{} basename {} .yaml 2>/dev/null | sort -u | grep -v "^$" || true)
        
        # Build JSON array
        if [ -z "$all_hostnames" ]; then
            json_response '{"success": true, "modified_devices": [], "count": 0}'
        else
            # Convert to JSON array using printf
            devices_json=$(echo "$all_hostnames" | while read -r h; do printf '"%s",' "$h"; done | sed 's/,$//')
            count=$(echo "$all_hostnames" | wc -l | tr -d ' ')
            json_response "{\"success\": true, \"modified_devices\": [${devices_json}], \"count\": ${count}}"
        fi
        ;;
    get-modified-files)
        # Get list of ALL modified files from git diff (for editor marking)
        cd "$ANSIBLE_DIR" || { json_response '{"success": false, "error": "Cannot access ansible directory"}'; exit 0; }
        git config --global --add safe.directory "$ANSIBLE_DIR" 2>/dev/null || true
        
        # Get modified files (staged and unstaged)
        modified=$(git diff --name-only 2>/dev/null || true)
        staged=$(git diff --cached --name-only 2>/dev/null || true)
        untracked=$(git ls-files --others --exclude-standard 2>/dev/null || true)
        
        # Combine all, make unique, filter hidden
        all_files=$(echo -e "${modified}\n${staged}\n${untracked}" | grep -v "^$" | grep -v "^\.git" | sort -u || true)
        
        # Build JSON array
        if [ -z "$all_files" ]; then
            json_response '{"success": true, "modified_files": [], "count": 0}'
        else
            files_json=$(echo "$all_files" | while read -r f; do printf '"%s",' "$f"; done | sed 's/,$//')
            count=$(echo "$all_files" | wc -l | tr -d ' ')
            json_response "{\"success\": true, \"modified_files\": [${files_json}], \"count\": ${count}}"
        fi
        ;;
    image)
        # Serve image file
        FILE=$(echo "$QUERY_STRING" | sed -n 's/.*file=\([^&]*\).*/\1/p' | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")
        FULL_PATH="$EDITOR_ROOT/$FILE"
        if [ -f "$FULL_PATH" ]; then
            EXT="${FILE##*.}"
            case "$EXT" in
                png) MIME="image/png" ;;
                jpg|jpeg) MIME="image/jpeg" ;;
                gif) MIME="image/gif" ;;
                svg) MIME="image/svg+xml" ;;
                *) MIME="application/octet-stream" ;;
            esac
            echo "Content-Type: $MIME"
            echo ""
            cat "$FULL_PATH"
        else
            echo "Status: 404 Not Found"
            echo "Content-Type: text/plain"
            echo ""
            echo "Image not found"
        fi
        exit 0
        ;;
    get-jinja-variables)
        # Extract Jinja2 variables from templates, group_vars, and host_vars
        cd "$ANSIBLE_DIR" || { json_response '{"success": false, "error": "Cannot access ansible directory"}'; exit 0; }
        
        # Collect all variables
        all_vars=""
        
        # 1. Scan .j2 templates for {{ variable }} patterns
        if [ -d "templates" ] || [ -d "roles" ]; then
            template_vars=$(find . -name "*.j2" -type f 2>/dev/null | xargs grep -ohE '\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)' 2>/dev/null | sed 's/{{[[:space:]]*//' | sort -u || true)
            all_vars="${all_vars}${template_vars}"$'\n'
        fi
        
        # 2. Scan group_vars YAML files for top-level keys
        if [ -d "inventory/group_vars" ]; then
            group_vars=$(find inventory/group_vars -name "*.yaml" -o -name "*.yml" 2>/dev/null | xargs grep -ohE '^[a-zA-Z_][a-zA-Z0-9_]*:' 2>/dev/null | sed 's/://' | sort -u || true)
            all_vars="${all_vars}${group_vars}"$'\n'
        fi
        
        # 3. Scan one host_vars file for schema (top-level keys)
        if [ -d "inventory/host_vars" ]; then
            sample_host=$(find inventory/host_vars -name "*.yaml" -type f 2>/dev/null | head -1)
            if [ -n "$sample_host" ]; then
                host_vars=$(grep -ohE '^[a-zA-Z_][a-zA-Z0-9_]*:' "$sample_host" 2>/dev/null | sed 's/://' | sort -u || true)
                all_vars="${all_vars}${host_vars}"$'\n'
            fi
        fi
        
        # 4. Scan roles defaults and vars
        if [ -d "roles" ]; then
            role_vars=$(find roles -path "*/defaults/*.yml" -o -path "*/defaults/*.yaml" -o -path "*/vars/*.yml" -o -path "*/vars/*.yaml" 2>/dev/null | xargs grep -ohE '^[a-zA-Z_][a-zA-Z0-9_]*:' 2>/dev/null | sed 's/://' | sort -u || true)
            all_vars="${all_vars}${role_vars}"$'\n'
        fi
        
        # Combine, deduplicate, filter
        unique_vars=$(echo "$all_vars" | grep -v "^$" | sort -u | grep -v "^#" | head -200)
        
        # Build JSON array
        if [ -z "$unique_vars" ]; then
            json_response '{"success": true, "variables": [], "count": 0}'
        else
            vars_json=$(echo "$unique_vars" | while read -r v; do [ -n "$v" ] && printf '"%s",' "$v"; done | sed 's/,$//')
            count=$(echo "$unique_vars" | wc -l | tr -d ' ')
            json_response "{\"success\": true, \"variables\": [${vars_json}], \"count\": ${count}}"
        fi
        ;;
    *)
        json_response '{"success": false, "error": "Unknown action"}'
        ;;
esac
