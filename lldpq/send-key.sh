#!/usr/bin/env bash
# send-key.sh - SSH Key Distribution + Sudo Setup
#
# Distributes SSH public keys and configures passwordless sudo
# on all devices defined in devices.yaml (in a single pass)
#
# Copyright (c) 2024-2026 LLDPq Project
# Licensed under MIT License - see LICENSE file for details
#
# USAGE:
#   ./send-key.sh                              # Interactive mode
#   ./send-key.sh -p "password"                # With password
#   ./send-key.sh -p "password" --no-sudo      # Key only, skip sudo setup
#   ./send-key.sh -p "password" --sudo-only    # Sudo only, skip key
#   ./send-key.sh -h                           # Help

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/load_devices.sh"
load_devices "$SCRIPT_DIR/parse_devices.py" || exit 1

# Prefer modern key types; first existing public key wins
DEFAULT_SSH_KEY="$HOME/.ssh/id_ed25519.pub"
for _key in id_ed25519 id_ecdsa id_rsa; do
    if [ -f "$HOME/.ssh/${_key}.pub" ]; then
        DEFAULT_SSH_KEY="$HOME/.ssh/${_key}.pub"
        break
    fi
done
SSH_KEY=""
PASSWORD=""
DO_KEY=true
DO_SUDO=true

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--password) PASSWORD="$2"; shift 2 ;;
        -k|--key) SSH_KEY="$2"; shift 2 ;;
        --no-sudo) DO_SUDO=false; shift ;;
        --sudo-only) DO_KEY=false; shift ;;
        -h|--help)
            echo "Usage: $0 [-p password] [-k ssh_key_path] [--no-sudo] [--sudo-only]"
            echo ""
            echo "  -p, --password    SSH password for initial authentication"
            echo "  -k, --key         Path to SSH public key (default: auto-detect ~/.ssh/id_{ed25519,ecdsa,rsa}.pub)"
            echo "  --no-sudo         Skip passwordless sudo setup (key distribution only)"
            echo "  --sudo-only       Skip key distribution (sudo setup only)"
            echo "  -h, --help        Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                          # Interactive: send key + sudo fix"
            echo "  $0 -p 'Nvidia@123'          # Non-interactive"
            echo "  $0 -p 'Nvidia@123' --no-sudo  # Key only"
            exit 0
            ;;
        *) echo "Unknown option: $1 (use -h for help)"; exit 1 ;;
    esac
done

check_dependencies() {
    if $DO_KEY; then
        if [ -z "$SSH_KEY" ]; then
            echo -e "${BLUE}SSH Key Selection${NC}"
            echo "=================================="
            if [ -f "$DEFAULT_SSH_KEY" ]; then
                echo -e "${GREEN}Default key found: ${DEFAULT_SSH_KEY}${NC}"
                echo -n -e "${YELLOW}Use this key? [Y/n]: ${NC}"
                read -r USE_DEFAULT
                if [[ "$USE_DEFAULT" =~ ^[Nn]$ ]]; then
                    echo -e "${YELLOW}Enter path to your SSH public key:${NC}"
                    read -r CUSTOM_KEY_PATH
                    CUSTOM_KEY_PATH="${CUSTOM_KEY_PATH/#\~/$HOME}"
                    if [ -f "$CUSTOM_KEY_PATH" ]; then
                        SSH_KEY="$CUSTOM_KEY_PATH"
                    else
                        echo -e "${RED}Key file not found: ${CUSTOM_KEY_PATH}${NC}"; exit 1
                    fi
                else
                    SSH_KEY="$DEFAULT_SSH_KEY"
                fi
            else
                echo -e "${YELLOW}Default SSH key not found: ${DEFAULT_SSH_KEY}${NC}"
                echo -n -e "${YELLOW}Generate new SSH key? [Y/n]: ${NC}"
                read -r GENERATE_KEY
                if [[ "$GENERATE_KEY" =~ ^[Nn]$ ]]; then
                    echo -e "${YELLOW}Enter path to your SSH public key:${NC}"
                    read -r CUSTOM_KEY_PATH
                    CUSTOM_KEY_PATH="${CUSTOM_KEY_PATH/#\~/$HOME}"
                    if [ -f "$CUSTOM_KEY_PATH" ]; then
                        SSH_KEY="$CUSTOM_KEY_PATH"
                    else
                        echo -e "${RED}Key file not found: ${CUSTOM_KEY_PATH}${NC}"; exit 1
                    fi
                else
                    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -q
                    if [ $? -eq 0 ]; then
                        SSH_KEY="$DEFAULT_SSH_KEY"
                        echo -e "${GREEN}SSH key generated: ${SSH_KEY}${NC}"
                    else
                        echo -e "${RED}Failed to generate SSH key${NC}"; exit 1
                    fi
                fi
            fi
            echo ""
        else
            SSH_KEY="${SSH_KEY/#\~/$HOME}"
            if [ ! -f "$SSH_KEY" ]; then
                echo -e "${RED}SSH key not found: ${SSH_KEY}${NC}"; exit 1
            fi
        fi
    fi

    if ! command -v sshpass &> /dev/null; then
        echo -e "${YELLOW}sshpass not found. Installing...${NC}"
        if sudo apt update -qq && sudo apt install -y -qq sshpass; then
            echo -e "${GREEN}sshpass installed${NC}"
        else
            echo -e "${RED}Failed to install sshpass${NC}"; exit 1
        fi
    fi
}

get_password() {
    if [ -z "$PASSWORD" ]; then
        echo -e "${YELLOW}Enter SSH password (used for all devices):${NC}"
        read -s PASSWORD
        echo ""
        [ -z "$PASSWORD" ] && echo -e "${RED}Password cannot be empty${NC}" && exit 1
    fi
}

process_device() {
    local device=$1
    local user=$2
    local hostname=$3
    local key_status="--"
    local sudo_status="--"

    # Step 1: SSH Key Distribution
    if $DO_KEY; then
        if ssh -o BatchMode=yes -o ConnectTimeout=5 -q "$user@$device" exit 2>/dev/null; then
            key_status="${GREEN}EXISTS${NC}"
        elif sshpass -p "$PASSWORD" ssh-copy-id -o StrictHostKeyChecking=no -i "$SSH_KEY" "$user@$device" 2>/dev/null; then
            key_status="${GREEN}SENT${NC}"
        else
            key_status="${RED}FAILED${NC}"
        fi
    fi

    # Step 2: Passwordless Sudo Setup
    if $DO_SUDO; then
        local pw_quoted
        pw_quoted=$(printf '%q' "$PASSWORD")
        local sudo_cmd="echo $pw_quoted | sudo -S bash -c 'echo \"$user ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/10_$user && chmod 440 /etc/sudoers.d/10_$user'"
        if sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -q "$user@$device" "$sudo_cmd" 2>/dev/null; then
            sudo_status="${GREEN}OK${NC}"
        else
            sudo_status="${RED}FAILED${NC}"
        fi
    fi

    echo -e "  ${hostname}\t${device}\tKey: ${key_status}\tSudo: ${sudo_status}"
}

main() {
    echo -e "${BLUE}LLDPq SSH Key + Sudo Setup${NC}"
    echo "=================================="

    check_dependencies
    get_password

    local total=${#devices[@]}
    echo -e "${BLUE}Processing $total devices...${NC}"
    echo ""

    local pids=()
    for device in "${!devices[@]}"; do
        IFS=' ' read -r user hostname <<< "${devices[$device]}"
        process_device "$device" "$user" "$hostname" &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait $pid
    done

    echo ""
    echo "=================================="
    echo -e "${GREEN}Done. Test: ssh <user>@<device> 'sudo whoami'${NC}"
}

main "$@"
