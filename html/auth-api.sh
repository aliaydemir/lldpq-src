#!/bin/bash
# LLDPq Authentication API
# Handles login, logout, session management, and password changes

# Configuration
USERS_FILE="/etc/lldpq-users.conf"
USERS_LOCK_FILE="/etc/lldpq-users.conf.lock"
AUTH_USERS_HELPER="/usr/local/libexec/lldpq-auth-users.py"
SESSIONS_DIR="/var/lib/lldpq/sessions"
SESSION_TIMEOUT=28800  # 8 hours in seconds
REMEMBER_TIMEOUT=604800  # 7 days in seconds

# Ensure sessions directory exists
mkdir -p "$SESSIONS_DIR" 2>/dev/null
chmod 700 "$SESSIONS_DIR" 2>/dev/null

# Get action from query string
ACTION=$(echo "$QUERY_STRING" | sed -n 's/.*action=\([^&]*\).*/\1/p')

# Read POST data if present
if [ "$REQUEST_METHOD" = "POST" ]; then
    read -n "$CONTENT_LENGTH" POST_DATA
fi

# Function to get POST parameter
get_post_param() {
    echo "$POST_DATA" | tr '&' '\n' | grep "^$1=" | cut -d'=' -f2 | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))"
}

# Function to generate random token
generate_token() {
    openssl rand -hex 32
}

# Function to hash password
hash_password() {
    printf '%s' "$1" | openssl dgst -sha256 | awk '{print $2}'
}

auth_users_mutate() {
    local action="$1" username="$2" password_hash="${3:-}"
    local payload result status
    payload=$(AUTH_MUTATION_ACTION="$action" \
        AUTH_MUTATION_USERNAME="$username" \
        AUTH_MUTATION_PASSWORD_HASH="$password_hash" \
        python3 -c 'import json,os
request={"action":os.environ["AUTH_MUTATION_ACTION"],
         "username":os.environ["AUTH_MUTATION_USERNAME"]}
password_hash=os.environ.get("AUTH_MUTATION_PASSWORD_HASH", "")
if password_hash:
    request["password_hash"]=password_hash
print(json.dumps(request, separators=(",", ":")))') || {
        echo '{"success":false,"error":"Could not encode users mutation"}'
        return 2
    }
    result=$(printf '%s' "$payload" | sudo -n "$AUTH_USERS_HELPER" 2>/dev/null)
    status=$?
    if [ -z "$result" ]; then
        echo '{"success":false,"error":"Users mutation helper failed; repair the installation"}'
        return 2
    fi
    printf '%s\n' "$result"
    return "$status"
}

# Function to get cookie
get_cookie() {
    echo "$HTTP_COOKIE" | tr ';' '\n' | grep "lldpq_session=" | cut -d'=' -f2 | tr -d ' '
}

valid_token() {
    [[ "$1" =~ ^[A-Fa-f0-9]{64}$ ]]
}

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'
}

get_user_record() {
    local username="$1"
    awk -F: -v u="$username" '$1 == u { print; exit }' "$USERS_FILE" 2>/dev/null
}

acquire_users_read_lock() {
    if ! exec {USERS_READ_LOCK_FD}<>"$USERS_LOCK_FILE"; then
        return 1
    fi
    if ! flock -s "$USERS_READ_LOCK_FD"; then
        exec {USERS_READ_LOCK_FD}>&-
        USERS_READ_LOCK_FD=""
        return 1
    fi
}

release_users_read_lock() {
    [ -n "${USERS_READ_LOCK_FD:-}" ] || return 0
    flock -u "$USERS_READ_LOCK_FD" 2>/dev/null || true
    exec {USERS_READ_LOCK_FD}>&-
    USERS_READ_LOCK_FD=""
}

# Function to validate session
validate_session() {
    local token="$1"
    if ! valid_token "$token"; then
        return 1
    fi
    local session_file="$SESSIONS_DIR/$token"
    
    if [ -z "$token" ] || [ ! -f "$session_file" ]; then
        return 1
    fi
    
    local expiry=$(head -1 "$session_file")
    local now=$(date +%s)
    
    if ! [[ "$expiry" =~ ^[0-9]+$ ]] || [ "$now" -gt "$expiry" ]; then
        rm -f "$session_file"
        return 1
    fi
    # A delete racing with login can create a session just after the delete
    # cleanup scan. Revalidate account existence/role on every session use so
    # such a session can never authenticate.
    local session_user session_role current_record current_role
    session_user=$(sed -n '2p' "$session_file" 2>/dev/null)
    session_role=$(sed -n '3p' "$session_file" 2>/dev/null)
    current_record=$(get_user_record "$session_user")
    current_role=$(printf '%s' "$current_record" | cut -d':' -f3)
    if [ -z "$current_record" ] || [ "$session_role" != "$current_role" ]; then
        rm -f "$session_file"
        return 1
    fi
    
    return 0
}

# Function to get session info
get_session_info() {
    local token="$1"
    if ! valid_token "$token"; then
        return 1
    fi
    local session_file="$SESSIONS_DIR/$token"
    
    if [ -f "$session_file" ]; then
        tail -n +2 "$session_file"
    fi
}

# Function to verify user credentials
verify_credentials() {
    local username="$1"
    local password="$2"
    
    if [ ! -f "$USERS_FILE" ]; then
        return 1
    fi
    
    local user_record=$(get_user_record "$username")
    local stored_hash=$(echo "$user_record" | cut -d':' -f2)
    local input_hash=$(hash_password "$password")
    
    if [ -z "$stored_hash" ]; then
        return 1
    fi
    
    if [ "$stored_hash" = "$input_hash" ]; then
        return 0
    fi
    
    return 1
}

# Function to get user role
get_user_role() {
    local username="$1"
    get_user_record "$username" | cut -d':' -f3
}

# Clean expired sessions
clean_sessions() {
    local now=$(date +%s)
    for session_file in "$SESSIONS_DIR"/*; do
        if [ -f "$session_file" ]; then
            local expiry=$(head -1 "$session_file" 2>/dev/null)
            if [ -n "$expiry" ] && [ "$now" -gt "$expiry" ]; then
                rm -f "$session_file"
            fi
        fi
    done
}

# Clean sessions occasionally (1 in 10 requests)
if [ $((RANDOM % 10)) -eq 0 ]; then
    clean_sessions
fi

# Output JSON header
json_response() {
    echo "Content-Type: application/json"
    echo ""
    echo "$1"
}

# Handle actions
case "$ACTION" in
    login)
        USERNAME=$(get_post_param "username")
        PASSWORD=$(get_post_param "password")
        REMEMBER=$(get_post_param "remember")

        if ! acquire_users_read_lock; then
            json_response '{"success": false, "error": "Authentication database is unavailable"}'
            exit 0
        fi
        if verify_credentials "$USERNAME" "$PASSWORD"; then
            TOKEN=$(generate_token)
            ROLE=$(get_user_role "$USERNAME")
            
            if [ "$REMEMBER" = "true" ]; then
                EXPIRY=$(($(date +%s) + REMEMBER_TIMEOUT))
                COOKIE_EXPIRY="Max-Age=$REMEMBER_TIMEOUT;"
            else
                EXPIRY=$(($(date +%s) + SESSION_TIMEOUT))
                COOKIE_EXPIRY=""
            fi
            
            # Create session file (single write)
            printf '%s\n%s\n%s\n' "$EXPIRY" "$USERNAME" "$ROLE" > "$SESSIONS_DIR/$TOKEN"
            release_users_read_lock
            
            # Set cookie and return success
            USERNAME_JSON=$(printf '%s' "$USERNAME" | json_escape)
            ROLE_JSON=$(printf '%s' "$ROLE" | json_escape)
            echo "Content-Type: application/json"
            echo "Set-Cookie: lldpq_session=$TOKEN; Path=/; HttpOnly; SameSite=Strict; $COOKIE_EXPIRY"
            echo ""
            echo "{\"success\": true, \"username\": $USERNAME_JSON, \"role\": $ROLE_JSON}"
        else
            release_users_read_lock
            json_response '{"success": false, "error": "Invalid username or password"}'
        fi
        ;;
        
    logout)
        TOKEN=$(get_cookie)
        if [ -n "$TOKEN" ]; then
            if valid_token "$TOKEN"; then
                rm -f "$SESSIONS_DIR/$TOKEN"
            fi
        fi
        
        echo "Content-Type: application/json"
        echo "Set-Cookie: lldpq_session=; Path=/; HttpOnly; Max-Age=0"
        echo ""
        echo '{"success": true}'
        ;;
        
    check)
        TOKEN=$(get_cookie)
        
        if validate_session "$TOKEN"; then
            INFO=$(get_session_info "$TOKEN")
            USERNAME=$(echo "$INFO" | head -1)
            ROLE=$(echo "$INFO" | tail -1)
            USERNAME_JSON=$(printf '%s' "$USERNAME" | json_escape)
            ROLE_JSON=$(printf '%s' "$ROLE" | json_escape)
            json_response "{\"authenticated\": true, \"username\": $USERNAME_JSON, \"role\": $ROLE_JSON}"
        else
            json_response '{"authenticated": false}'
        fi
        ;;
        
    change-password)
        TOKEN=$(get_cookie)
        
        if ! validate_session "$TOKEN"; then
            json_response '{"success": false, "error": "Not authenticated"}'
            exit 0
        fi
        
        INFO=$(get_session_info "$TOKEN")
        CURRENT_USER=$(echo "$INFO" | head -1)
        CURRENT_ROLE=$(echo "$INFO" | tail -1)
        
        # Only admin can change passwords
        if [ "$CURRENT_ROLE" != "admin" ]; then
            json_response '{"success": false, "error": "Permission denied"}'
            exit 0
        fi
        
        TARGET_USER=$(get_post_param "target_user")
        NEW_PASSWORD=$(get_post_param "new_password")
        
        # Validate password length
        if [ ${#NEW_PASSWORD} -lt 6 ]; then
            json_response '{"success": false, "error": "Password must be at least 6 characters"}'
            exit 0
        fi
        
        # Hash new password
        NEW_HASH=$(hash_password "$NEW_PASSWORD")
        
        RESULT=$(auth_users_mutate change-password "$TARGET_USER" "$NEW_HASH")
        json_response "$RESULT"
        ;;
    
    list-users)
        TOKEN=$(get_cookie)
        
        if ! validate_session "$TOKEN"; then
            json_response '{"success": false, "error": "Not authenticated"}'
            exit 0
        fi
        
        INFO=$(get_session_info "$TOKEN")
        CURRENT_ROLE=$(echo "$INFO" | tail -1)
        
        # Only admin can list users
        if [ "$CURRENT_ROLE" != "admin" ]; then
            json_response '{"success": false, "error": "Permission denied"}'
            exit 0
        fi
        
        # Build JSON array of users (exclude password hash)
        USERS_JSON="["
        FIRST=true
        while IFS=':' read -r username hash role; do
            if [ -n "$username" ]; then
                if [ "$FIRST" = true ]; then
                    FIRST=false
                else
                    USERS_JSON="$USERS_JSON,"
                fi
                username_json=$(printf '%s' "$username" | json_escape)
                role_json=$(printf '%s' "$role" | json_escape)
                USERS_JSON="$USERS_JSON{\"username\":$username_json,\"role\":$role_json}"
            fi
        done < "$USERS_FILE"
        USERS_JSON="$USERS_JSON]"
        
        json_response "{\"success\": true, \"users\": $USERS_JSON}"
        ;;
    
    create-user)
        TOKEN=$(get_cookie)
        
        if ! validate_session "$TOKEN"; then
            json_response '{"success": false, "error": "Not authenticated"}'
            exit 0
        fi
        
        INFO=$(get_session_info "$TOKEN")
        CURRENT_ROLE=$(echo "$INFO" | tail -1)
        
        # Only admin can create users
        if [ "$CURRENT_ROLE" != "admin" ]; then
            json_response '{"success": false, "error": "Permission denied"}'
            exit 0
        fi
        
        NEW_USERNAME=$(get_post_param "username")
        NEW_PASSWORD=$(get_post_param "password")
        
        # Validate username (alphanumeric, 3-20 chars)
        if ! echo "$NEW_USERNAME" | grep -qE '^[a-zA-Z][a-zA-Z0-9_-]{2,19}$'; then
            json_response '{"success": false, "error": "Invalid username. Use 3-20 alphanumeric characters, starting with a letter."}'
            exit 0
        fi
        
        # Validate password length
        if [ ${#NEW_PASSWORD} -lt 6 ]; then
            json_response '{"success": false, "error": "Password must be at least 6 characters"}'
            exit 0
        fi
        
        # Hash password; the locked root-owned helper performs duplicate and
        # protected-admin checks against the post-lock snapshot.
        NEW_HASH=$(hash_password "$NEW_PASSWORD")
        RESULT=$(auth_users_mutate create-user "$NEW_USERNAME" "$NEW_HASH")
        json_response "$RESULT"
        ;;
    
    delete-user)
        TOKEN=$(get_cookie)
        
        if ! validate_session "$TOKEN"; then
            json_response '{"success": false, "error": "Not authenticated"}'
            exit 0
        fi
        
        INFO=$(get_session_info "$TOKEN")
        CURRENT_USER=$(echo "$INFO" | head -1)
        CURRENT_ROLE=$(echo "$INFO" | tail -1)
        
        # Only admin can delete users
        if [ "$CURRENT_ROLE" != "admin" ]; then
            json_response '{"success": false, "error": "Permission denied"}'
            exit 0
        fi
        
        TARGET_USER=$(get_post_param "username")
        
        # Cannot delete admin user
        if [ "$TARGET_USER" = "admin" ]; then
            json_response '{"success": false, "error": "Cannot delete admin user"}'
            exit 0
        fi
        
        # Cannot delete yourself
        if [ "$TARGET_USER" = "$CURRENT_USER" ]; then
            json_response '{"success": false, "error": "Cannot delete yourself"}'
            exit 0
        fi
        
        RESULT=$(auth_users_mutate delete-user "$TARGET_USER")
        MUTATION_STATUS=$?
        if [ "$MUTATION_STATUS" -ne 0 ]; then
            json_response "$RESULT"
            exit 0
        fi
        
        # Remove any active sessions for this user
        for session_file in "$SESSIONS_DIR"/*; do
            if [ -f "$session_file" ]; then
                SESSION_USER=$(sed -n '2p' "$session_file" 2>/dev/null)
                if [ "$SESSION_USER" = "$TARGET_USER" ]; then
                    rm -f "$session_file"
                fi
            fi
        done
        
        json_response "$RESULT"
        ;;
        
    *)
        json_response '{"error": "Unknown action"}'
        ;;
esac
