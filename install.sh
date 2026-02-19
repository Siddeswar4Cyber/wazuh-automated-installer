#!/usr/bin/env bash
#
# Wazuh 4.14 Automated Installer - Production Version
# Author: Siddeswar (DevOps Team) / Refactored by Senior DevOps
# License: MIT
#
# Usage: sudo ./install.sh
#
# This script automates the installation of Wazuh Indexer, Server, and Dashboard
# on a single node using the official Wazuh installer.

set -euo pipefail

# --------------------------------------------
# Global Variables & Configuration
# --------------------------------------------
readonly WAZUH_VERSION="4.14"
readonly BASE_URL="https://packages.wazuh.com/${WAZUH_VERSION}"
readonly LOGFILE="/var/log/wazuh-install.log"
readonly TMP_DIR="/tmp/wazuh-install-$$"  # Unique temp directory
readonly MIN_DISK_SPACE_MB=5120           # 5 GB minimum for /var
readonly MAX_RETRIES=3
readonly RETRY_DELAY=5

# Colors for console output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly NC='\033[0m' # No Color

# Ensure we start with a clean slate
mkdir -p "$TMP_DIR"
cd "$TMP_DIR"

# Trap to clean up on exit or error
trap cleanup EXIT INT TERM

# --------------------------------------------
# Logging Functions
# --------------------------------------------
log_info() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $*" | tee -a "$LOGFILE"
}

log_warn() {
    echo -e "${YELLOW}$(date '+%Y-%m-%d %H:%M:%S') [WARN]  $*${NC}" | tee -a "$LOGFILE"
}

log_error() {
    echo -e "${RED}$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $*${NC}" | tee -a "$LOGFILE" >&2
}

# Print sensitive data only to console (not to log)
log_sensitive() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  $*" 
    # Log a redacted version
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO]  ******** (sensitive output suppressed)" >> "$LOGFILE"
}

# --------------------------------------------
# Cleanup Function
# --------------------------------------------
cleanup() {
    local exit_code=$?
    if [[ -d "$TMP_DIR" ]]; then
        log_info "Cleaning up temporary directory: $TMP_DIR"
        rm -rf "$TMP_DIR"
    fi
    if [[ $exit_code -ne 0 ]]; then
        log_error "Installation failed with exit code $exit_code. Check $LOGFILE for details."
    else
        log_info "Installation completed successfully."
    fi
    exit "$exit_code"
}

# --------------------------------------------
# Prerequisite Checks
# --------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo ./install.sh"
        exit 1
    fi
}

check_commands() {
    local required_commands=("curl" "tar" "awk" "sed" "ip" "grep" "apt")
    local missing=()
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing[*]}. Please install them and rerun."
        exit 1
    fi
}

check_internet() {
    log_info "Checking internet connectivity..."
    if ! curl --fail --silent --head "$BASE_URL" >/dev/null; then
        log_error "Cannot reach $BASE_URL. Check your internet connection."
        exit 1
    fi
}

check_disk_space() {
    log_info "Checking disk space on /var..."
    local available_mb
    available_mb=$(df -m /var | awk 'NR==2 {print $4}')
    if [[ $available_mb -lt $MIN_DISK_SPACE_MB ]]; then
        log_error "Insufficient disk space on /var: ${available_mb}MB available, need at least ${MIN_DISK_SPACE_MB}MB."
        exit 1
    fi
    log_info "Disk space OK (${available_mb}MB available)."
}

detect_ip() {
    log_info "Detecting primary IP address..."
    local ip
    # Try to get IPv4 address of the default route interface
    ip=$(ip -4 route get 1 2>/dev/null | awk '{print $7; exit}')
    if [[ -z "$ip" ]]; then
        # Fallback: get first non-loopback IPv4
        ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -1)
    fi
    if [[ -z "$ip" ]]; then
        log_error "Could not detect IP address automatically."
        exit 1
    fi
    # Validate format
    if ! [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_error "Detected IP '$ip' is not a valid IPv4 address."
        exit 1
    fi
    echo "$ip"
}

# --------------------------------------------
# Installation Functions
# --------------------------------------------
install_dependencies() {
    log_info "Installing required system packages..."
    apt update -y >> "$LOGFILE" 2>&1
    apt install -y curl tar >> "$LOGFILE" 2>&1
    # iproute2 is usually preinstalled, but ensure it's there
    apt install -y iproute2 >> "$LOGFILE" 2>&1
}

download_file_with_retry() {
    local url="$1"
    local output="$2"
    local attempt=1
    while [[ $attempt -le $MAX_RETRIES ]]; do
        log_info "Downloading $url (attempt $attempt/$MAX_RETRIES)..."
        if curl --fail --location --silent --show-error --output "$output" "$url"; then
            log_info "Downloaded $output successfully."
            return 0
        fi
        log_warn "Download failed. Retrying in $RETRY_DELAY seconds..."
        sleep "$RETRY_DELAY"
        ((attempt++))
    done
    log_error "Failed to download $url after $MAX_RETRIES attempts."
    exit 1
}

configure_files() {
    local ip="$1"
    log_info "Configuring config.yml with IP $ip..."
    # Use a different delimiter in sed to avoid issues with IP dots
    sed -i "s|<indexer-node-ip>|${ip}|g" config.yml
    sed -i "s|<wazuh-manager-ip>|${ip}|g" config.yml
    sed -i "s|<dashboard-node-ip>|${ip}|g" config.yml
}

run_wazuh_installer() {
    local args=("$@")
    log_info "Running: ./wazuh-install.sh ${args[*]}"
    # Redirect output to log but also capture exit code
    if ! ./wazuh-install.sh "${args[@]}" >> "$LOGFILE" 2>&1; then
        log_error "wazuh-install.sh ${args[*]} failed. Check $LOGFILE."
        exit 1
    fi
}

wait_for_api() {
    local ip="$1"
    local password="$2"
    local max_attempts=30
    local attempt=1
    log_info "Waiting for Wazuh Indexer API to be ready at https://${ip}:9200 ..."
    while [[ $attempt -le $max_attempts ]]; do
        if curl -k -s -o /dev/null -w "%{http_code}" -u "admin:${password}" "https://${ip}:9200" | grep -q "200"; then
            log_info "Indexer API is responsive."
            return 0
        fi
        log_info "Attempt $attempt/$max_attempts: API not ready yet. Waiting 5 seconds..."
        sleep 5
        ((attempt++))
    done
    log_error "Indexer API failed to respond within $((max_attempts * 5)) seconds."
    exit 1
}

extract_password() {
    log_info "Extracting admin password from wazuh-install-files.tar..."
    if [[ ! -f wazuh-install-files.tar ]]; then
        log_error "wazuh-install-files.tar not found."
        exit 1
    fi
    # Extract the password file to stdout and parse it
    local password
    password=$(tar -xf wazuh-install-files.tar -O wazuh-install-files/wazuh-passwords.txt 2>/dev/null | \
               grep -A1 "indexer_username: 'admin'" | \
               grep "indexer_password" | \
               awk -F"'" '{print $2}')
    if [[ -z "$password" ]]; then
        log_error "Failed to extract admin password from wazuh-passwords.txt."
        exit 1
    fi
    echo "$password"
}

# --------------------------------------------
# Main Installation Flow
# --------------------------------------------
main() {
    log_info "========== WAZUH $WAZUH_VERSION AUTOMATED INSTALLATION =========="

    # 1. Prerequisites
    check_root
    check_commands
    check_internet
    check_disk_space

    # 2. Detect IP
    local ip_address
    ip_address=$(detect_ip)
    log_info "Detected IP: $ip_address"

    # 3. Install dependencies
    install_dependencies

    # 4. Download Wazuh installer and config template
    download_file_with_retry "${BASE_URL}/wazuh-install.sh" "wazuh-install.sh"
    download_file_with_retry "${BASE_URL}/config.yml" "config.yml"
    chmod +x wazuh-install.sh

    # 5. Configure config.yml
    configure_files "$ip_address"

    # 6. Generate configuration files
    run_wazuh_installer --generate-config-files

    # 7. Install Wazuh Indexer
    run_wazuh_installer --wazuh-indexer node-1

    # 8. Start indexer cluster
    run_wazuh_installer --start-cluster

    # 9. Extract admin password
    local admin_password
    admin_password=$(extract_password)
    log_sensitive "Admin password retrieved (hidden from log)."

    # 10. Wait for Indexer API to be ready
    wait_for_api "$ip_address" "$admin_password"

    # 11. Install Wazuh Server
    run_wazuh_installer --wazuh-server wazuh-1

    # 12. Install Wazuh Dashboard
    run_wazuh_installer --wazuh-dashboard dashboard

    # 13. Final output (password only to console, not logged)
    echo ""
    echo "========== INSTALLATION COMPLETE =========="
    echo "Dashboard URL : https://${ip_address}"
    echo "Username      : admin"
    echo "Password      : ${admin_password}"
    echo ""
    echo "⚠️  Browser will show a certificate warning – accept the self-signed certificate."
    echo "📄 Full installation log: $LOGFILE"
    log_info "Final output displayed on console (password redacted from log)."
}

# Run main function
main