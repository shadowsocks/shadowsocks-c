#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# ss-setup -- Interactive TUI for shadowsocks-libev server/client setup
#
# Requires: whiptail or dialog, openssl (optional), curl (for plugin install)
# Usage:    sudo ss-setup          (full server setup + service management)
#           ss-setup               (config generation only, no service install)
###############################################################################

readonly SS_SETUP_VERSION="1.0.0"
readonly CONFIG_DIR="/etc/shadowsocks-libev"
readonly SYSTEMD_UNIT_DIR="/etc/systemd/system"
readonly SYSTEMD_TEMPLATE="shadowsocks-libev-server@.service"

# AEAD ciphers supported by shadowsocks-libev (from src/aead.cpp)
readonly AEAD_CIPHERS=(
    "chacha20-ietf-poly1305"
    "aes-256-gcm"
    "aes-192-gcm"
    "aes-128-gcm"
    "xchacha20-ietf-poly1305"
)

# Known SIP003 plugins and their GitHub repos
# Using a function instead of associative array for bash 3.x compatibility
plugin_repo() {
    case "$1" in
        simple-obfs)   echo "shadowsocks/simple-obfs" ;;
        v2ray-plugin)  echo "shadowsocks/v2ray-plugin" ;;
        xray-plugin)   echo "teddysun/xray-plugin" ;;
        kcptun)        echo "xtaci/kcptun" ;;
        *)             echo "" ;;
    esac
}

readonly KNOWN_PLUGINS=("simple-obfs" "v2ray-plugin" "xray-plugin" "kcptun")

# Globals set by the setup flows
TUI_BACKEND=""
TMPDIR_CLEANUP=""

# Server config globals
CFG_SERVER="0.0.0.0"
CFG_SERVER_PORT="8388"
CFG_METHOD="chacha20-ietf-poly1305"
CFG_PASSWORD=""
CFG_TIMEOUT="300"
CFG_MODE="tcp_and_udp"
CFG_FAST_OPEN="false"
CFG_PLUGIN=""
CFG_PLUGIN_OPTS=""
CFG_INSTANCE_NAME="config"

# Client config globals
CFG_CLIENT_SERVER=""
CFG_CLIENT_SERVER_PORT="8388"
CFG_CLIENT_LOCAL_PORT="1080"
CFG_CLIENT_METHOD="chacha20-ietf-poly1305"
CFG_CLIENT_PASSWORD=""
CFG_CLIENT_PLUGIN=""
CFG_CLIENT_PLUGIN_OPTS=""
CFG_CLIENT_OUTPUT=""

###############################################################################
# Cleanup
###############################################################################

cleanup() {
    if [[ -n "${TMPDIR_CLEANUP}" && -d "${TMPDIR_CLEANUP}" ]]; then
        rm -rf "${TMPDIR_CLEANUP}"
    fi
}
# Only set trap when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    trap cleanup EXIT
fi

###############################################################################
# TUI Backend Detection & Wrappers
###############################################################################

detect_tui_backend() {
    if command -v whiptail >/dev/null 2>&1; then
        TUI_BACKEND="whiptail"
    elif command -v dialog >/dev/null 2>&1; then
        TUI_BACKEND="dialog"
    else
        echo "Error: neither whiptail nor dialog found." >&2
        echo "Install one of them:" >&2
        echo "  Debian/Ubuntu: sudo apt install whiptail" >&2
        echo "  RHEL/Fedora:   sudo dnf install newt" >&2
        echo "  Arch:          sudo pacman -S libnewt" >&2
        exit 1
    fi
}

# tui_msgbox title message
tui_msgbox() {
    local title="$1" msg="$2"
    $TUI_BACKEND --title "$title" --msgbox "$msg" 20 70
}

# tui_yesno title message → exit code 0=yes 1=no
tui_yesno() {
    local title="$1" msg="$2"
    if $TUI_BACKEND --title "$title" --yesno "$msg" 12 70; then
        return 0
    else
        return 1
    fi
}

# tui_inputbox title message default → prints value
tui_inputbox() {
    local title="$1" msg="$2" default="${3:-}"
    local result
    result=$($TUI_BACKEND --title "$title" --inputbox "$msg" 10 70 "$default" 3>&1 1>&2 2>&3) || return $?
    echo "$result"
}

# tui_passwordbox title message → prints value
tui_passwordbox() {
    local title="$1" msg="$2"
    local result
    result=$($TUI_BACKEND --title "$title" --passwordbox "$msg" 10 70 3>&1 1>&2 2>&3) || return $?
    echo "$result"
}

# tui_menu title message tag1 item1 tag2 item2 ... → prints selected tag
tui_menu() {
    local title="$1" msg="$2"
    shift 2
    local items=("$@")
    local count=$(( ${#items[@]} / 2 ))
    local result
    result=$($TUI_BACKEND --title "$title" --menu "$msg" 20 70 "$count" "${items[@]}" 3>&1 1>&2 2>&3) || return $?
    echo "$result"
}

# tui_radiolist title message tag1 item1 status1 ... → prints selected tag
tui_radiolist() {
    local title="$1" msg="$2"
    shift 2
    local items=("$@")
    local count=$(( ${#items[@]} / 3 ))
    local result
    result=$($TUI_BACKEND --title "$title" --radiolist "$msg" 20 70 "$count" "${items[@]}" 3>&1 1>&2 2>&3) || return $?
    echo "$result"
}

###############################################################################
# Utility Functions
###############################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        tui_msgbox "Notice" "Not running as root.\n\nYou can still generate config files, but service installation and plugin management will be skipped.\n\nRe-run with sudo for full functionality."
        return 1
    fi
    return 0
}

is_root() {
    [[ $EUID -eq 0 ]]
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        return 0
    fi
    return 1
}

validate_instance_name() {
    local name="$1"
    if [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        return 0
    fi
    return 1
}

generate_password() {
    local len="${1:-32}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 "$len" | tr -d '\n'
    else
        head -c "$len" /dev/urandom | base64 | tr -d '\n'
    fi
}

generate_random_port() {
    local port
    if [[ -r /dev/urandom ]]; then
        port=$(( ($(od -An -tu2 -N2 /dev/urandom | tr -d ' ') % 55001) + 10000 ))
    else
        port=$(( (RANDOM % 55001) + 10000 ))
    fi
    echo "$port"
}

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo -n "$str"
}

urlencode() {
    local str="$1"
    local encoded=""
    local i c
    for (( i = 0; i < ${#str}; i++ )); do
        c="${str:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *) encoded+=$(printf '%%%02X' "'$c") ;;
        esac
    done
    echo -n "$encoded"
}

# Generate SIP002 ss:// URI
# ss://BASE64URL(method:password)@host:port[/?plugin=URLENCODE(plugin;opts)]
generate_ss_uri() {
    local method="$1" password="$2" server="$3" port="$4"
    local plugin="${5:-}" plugin_opts="${6:-}"

    local userinfo
    userinfo=$(echo -n "${method}:${password}" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')

    local uri="ss://${userinfo}@${server}:${port}"

    if [[ -n "$plugin" ]]; then
        local plugin_str="$plugin"
        if [[ -n "$plugin_opts" ]]; then
            plugin_str="${plugin};${plugin_opts}"
        fi
        uri="${uri}/?plugin=$(urlencode "$plugin_str")"
    fi

    echo "$uri"
}

# Write JSON config from CFG_* globals (server mode)
# Produces valid JSON with no trailing commas; booleans unquoted
write_json_config() {
    local outfile="$1"
    local fast_open_val="false"
    [[ "$CFG_FAST_OPEN" == "true" ]] && fast_open_val="true"

    {
        printf '{\n'
        printf '    "server": "%s",\n' "$(json_escape "$CFG_SERVER")"
        printf '    "server_port": %s,\n' "$CFG_SERVER_PORT"
        printf '    "password": "%s",\n' "$(json_escape "$CFG_PASSWORD")"
        printf '    "timeout": %s,\n' "$CFG_TIMEOUT"
        printf '    "method": "%s",\n' "$(json_escape "$CFG_METHOD")"
        printf '    "mode": "%s",\n' "$(json_escape "$CFG_MODE")"
        if [[ -n "$CFG_PLUGIN" ]]; then
            printf '    "fast_open": %s,\n' "$fast_open_val"
            printf '    "plugin": "%s"' "$(json_escape "$CFG_PLUGIN")"
            if [[ -n "$CFG_PLUGIN_OPTS" ]]; then
                printf ',\n'
                printf '    "plugin_opts": "%s"' "$(json_escape "$CFG_PLUGIN_OPTS")"
            fi
        else
            printf '    "fast_open": %s' "$fast_open_val"
        fi
        printf '\n}\n'
    } > "$outfile"
}

# Write JSON config for client mode
write_client_json_config() {
    local outfile="$1"

    {
        printf '{\n'
        printf '    "server": "%s",\n' "$(json_escape "$CFG_CLIENT_SERVER")"
        printf '    "server_port": %s,\n' "$CFG_CLIENT_SERVER_PORT"
        printf '    "local_address": "127.0.0.1",\n'
        printf '    "local_port": %s,\n' "$CFG_CLIENT_LOCAL_PORT"
        printf '    "password": "%s",\n' "$(json_escape "$CFG_CLIENT_PASSWORD")"
        printf '    "timeout": 300,\n'
        printf '    "method": "%s",\n' "$(json_escape "$CFG_CLIENT_METHOD")"
        if [[ -n "$CFG_CLIENT_PLUGIN" ]]; then
            printf '    "mode": "tcp_and_udp",\n'
            printf '    "plugin": "%s"' "$(json_escape "$CFG_CLIENT_PLUGIN")"
            if [[ -n "$CFG_CLIENT_PLUGIN_OPTS" ]]; then
                printf ',\n'
                printf '    "plugin_opts": "%s"' "$(json_escape "$CFG_CLIENT_PLUGIN_OPTS")"
            fi
        else
            printf '    "mode": "tcp_and_udp"'
        fi
        printf '\n}\n'
    } > "$outfile"
}

# Parse an existing config file and populate CFG_* globals
parse_existing_config() {
    local file="$1"
    local val

    val=$(grep -o '"server"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" | head -1 | sed 's/.*:.*"\(.*\)"/\1/') && [[ -n "$val" ]] && CFG_SERVER="$val"
    val=$(grep -o '"server_port"[[:space:]]*:[[:space:]]*[0-9]*' "$file" | head -1 | sed 's/.*:[[:space:]]*//')  && [[ -n "$val" ]] && CFG_SERVER_PORT="$val"
    val=$(grep -o '"password"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" | head -1 | sed 's/.*:.*"\(.*\)"/\1/')    && [[ -n "$val" ]] && CFG_PASSWORD="$val"
    val=$(grep -o '"method"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" | head -1 | sed 's/.*:.*"\(.*\)"/\1/')      && [[ -n "$val" ]] && CFG_METHOD="$val"
    val=$(grep -o '"timeout"[[:space:]]*:[[:space:]]*[0-9]*' "$file" | head -1 | sed 's/.*:[[:space:]]*//')       && [[ -n "$val" ]] && CFG_TIMEOUT="$val"
    val=$(grep -o '"mode"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" | head -1 | sed 's/.*:.*"\(.*\)"/\1/')         && [[ -n "$val" ]] && CFG_MODE="$val"
    val=$(grep -o '"fast_open"[[:space:]]*:[[:space:]]*[a-z]*' "$file" | head -1 | sed 's/.*:[[:space:]]*//')     && [[ -n "$val" ]] && CFG_FAST_OPEN="$val"
    val=$(grep -o '"plugin"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" | head -1 | sed 's/.*:.*"\(.*\)"/\1/')       && [[ -n "$val" ]] && CFG_PLUGIN="$val"
    val=$(grep -o '"plugin_opts"[[:space:]]*:[[:space:]]*"[^"]*"' "$file" | head -1 | sed 's/.*:.*"\(.*\)"/\1/')  && [[ -n "$val" ]] && CFG_PLUGIN_OPTS="$val"

    return 0
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7*|armhf)  echo "armv7" ;;
        i686|i386)     echo "386" ;;
        *)             echo "$arch" ;;
    esac
}

detect_os() {
    local os
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$os" in
        linux*)  echo "linux" ;;
        darwin*) echo "darwin" ;;
        *)       echo "$os" ;;
    esac
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${ID:-unknown}"
    elif command -v lsb_release >/dev/null 2>&1; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

has_systemd() {
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

systemd_version() {
    local ver
    ver=$(systemctl --version 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -1) || ver="0"
    echo "$ver"
}

check_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tlnp 2>/dev/null | grep -q ":${port} " && return 0
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tlnp 2>/dev/null | grep -q ":${port} " && return 0
    fi
    return 1
}

find_installed_plugins() {
    local plugins=()
    local p
    for p in "${KNOWN_PLUGINS[@]}"; do
        if command -v "$p" >/dev/null 2>&1; then
            plugins+=("$p")
        fi
    done
    # Also check obfs-local (simple-obfs installs as obfs-local/obfs-server)
    if command -v obfs-local >/dev/null 2>&1; then
        local found=0
        for p in "${plugins[@]}"; do
            [[ "$p" == "simple-obfs" ]] && found=1
        done
        [[ $found -eq 0 ]] && plugins+=("obfs-local")
    fi
    echo "${plugins[*]}"
}

###############################################################################
# Server Setup Flow
###############################################################################

server_ask_listen_address() {
    local addr
    while true; do
        addr=$(tui_inputbox "Listen Address" "Enter the server listen address:" "$CFG_SERVER") || return 1
        if [[ -n "$addr" ]]; then
            CFG_SERVER="$addr"
            return 0
        fi
        tui_msgbox "Error" "Address cannot be empty."
    done
}

server_ask_port() {
    local choice
    choice=$(tui_menu "Server Port" "Choose how to set the server port:" \
        "manual" "Enter port manually (default: ${CFG_SERVER_PORT})" \
        "random" "Generate a random high port") || return 1

    if [[ "$choice" == "random" ]]; then
        CFG_SERVER_PORT=$(generate_random_port)
        tui_msgbox "Random Port" "Selected port: ${CFG_SERVER_PORT}"
        return 0
    fi

    local port
    while true; do
        port=$(tui_inputbox "Server Port" "Enter the server port (1-65535):" "$CFG_SERVER_PORT") || return 1
        if validate_port "$port"; then
            if check_port_in_use "$port"; then
                if ! tui_yesno "Port In Use" "Port ${port} appears to be in use.\n\nContinue anyway?"; then
                    continue
                fi
            fi
            CFG_SERVER_PORT="$port"
            return 0
        fi
        tui_msgbox "Error" "Invalid port number. Must be 1-65535."
    done
}

server_ask_method() {
    local items=()
    local cipher
    for cipher in "${AEAD_CIPHERS[@]}"; do
        if [[ "$cipher" == "$CFG_METHOD" ]]; then
            items+=("$cipher" "" "ON")
        else
            items+=("$cipher" "" "OFF")
        fi
    done

    local method
    method=$(tui_radiolist "Encryption Method" "Select the AEAD cipher to use:" "${items[@]}") || return 1
    CFG_METHOD="$method"
}

server_ask_password() {
    if tui_yesno "Password" "Auto-generate a secure random password?\n\n(Select No to enter manually)"; then
        CFG_PASSWORD=$(generate_password 32)
        tui_msgbox "Generated Password" "Password (save this!):\n\n${CFG_PASSWORD}"
        return 0
    fi

    local pass1 pass2
    while true; do
        pass1=$(tui_passwordbox "Password" "Enter the password:") || return 1
        if [[ -z "$pass1" ]]; then
            tui_msgbox "Error" "Password cannot be empty."
            continue
        fi
        pass2=$(tui_passwordbox "Confirm Password" "Confirm the password:") || return 1
        if [[ "$pass1" == "$pass2" ]]; then
            CFG_PASSWORD="$pass1"
            return 0
        fi
        tui_msgbox "Error" "Passwords do not match. Try again."
    done
}

server_ask_timeout() {
    local timeout
    while true; do
        timeout=$(tui_inputbox "Timeout" "Connection timeout in seconds:" "$CFG_TIMEOUT") || return 1
        if [[ "$timeout" =~ ^[0-9]+$ ]] && (( timeout > 0 )); then
            CFG_TIMEOUT="$timeout"
            return 0
        fi
        tui_msgbox "Error" "Timeout must be a positive integer."
    done
}

server_ask_mode() {
    local items=()
    local modes=("tcp_only" "tcp_and_udp" "udp_only")
    local m
    for m in "${modes[@]}"; do
        if [[ "$m" == "$CFG_MODE" ]]; then
            items+=("$m" "" "ON")
        else
            items+=("$m" "" "OFF")
        fi
    done

    local mode
    mode=$(tui_radiolist "Network Mode" "Select the network mode:" "${items[@]}") || return 1
    CFG_MODE="$mode"
}

server_ask_fast_open() {
    # Check if TCP Fast Open is available (Linux only)
    if [[ -f /proc/sys/net/ipv4/tcp_fastopen ]]; then
        local tfo_val
        tfo_val=$(cat /proc/sys/net/ipv4/tcp_fastopen 2>/dev/null) || tfo_val="0"
        if (( tfo_val >= 2 )); then
            CFG_FAST_OPEN="true"
        fi
        if tui_yesno "TCP Fast Open" "Enable TCP Fast Open?\n\n(Current kernel setting: ${tfo_val})\nRequires kernel support and sysctl net.ipv4.tcp_fastopen >= 2 for server."; then
            CFG_FAST_OPEN="true"
        else
            CFG_FAST_OPEN="false"
        fi
    else
        CFG_FAST_OPEN="false"
        tui_msgbox "TCP Fast Open" "TCP Fast Open is not available on this system.\nSetting to disabled."
    fi
}

server_ask_plugin() {
    local installed
    installed=$(find_installed_plugins)

    local items=("none" "No plugin")
    local p
    for p in $installed; do
        items+=("$p" "$(command -v "$p" 2>/dev/null || echo "$p")")
    done
    items+=("custom" "Enter custom plugin path")

    local choice
    choice=$(tui_menu "SIP003 Plugin" "Select a plugin (optional):" "${items[@]}") || return 1

    if [[ "$choice" == "none" ]]; then
        CFG_PLUGIN=""
        CFG_PLUGIN_OPTS=""
        return 0
    fi

    if [[ "$choice" == "custom" ]]; then
        local plugin_path
        plugin_path=$(tui_inputbox "Custom Plugin" "Enter the plugin binary name or full path:" "") || return 1
        if [[ -z "$plugin_path" ]]; then
            CFG_PLUGIN=""
            CFG_PLUGIN_OPTS=""
            return 0
        fi
        CFG_PLUGIN="$plugin_path"
    else
        CFG_PLUGIN="$choice"
    fi

    local opts
    opts=$(tui_inputbox "Plugin Options" "Enter plugin options (or leave empty):" "$CFG_PLUGIN_OPTS") || return 1
    CFG_PLUGIN_OPTS="$opts"
}

server_ask_instance_name() {
    local name
    while true; do
        name=$(tui_inputbox "Instance Name" "Enter a name for this config instance.\nThe config will be saved as ${CONFIG_DIR}/<name>.json" "$CFG_INSTANCE_NAME") || return 1
        if ! validate_instance_name "$name"; then
            tui_msgbox "Error" "Invalid name. Use only letters, numbers, hyphens, and underscores."
            continue
        fi
        if [[ -f "${CONFIG_DIR}/${name}.json" ]]; then
            local action
            action=$(tui_menu "Config Exists" "Config '${name}.json' already exists:" \
                "overwrite" "Overwrite the existing config" \
                "edit" "Load and edit the existing config" \
                "rename" "Choose a different name") || return 1
            case "$action" in
                overwrite)
                    CFG_INSTANCE_NAME="$name"
                    return 0
                    ;;
                edit)
                    parse_existing_config "${CONFIG_DIR}/${name}.json"
                    CFG_INSTANCE_NAME="$name"
                    return 2  # signal to restart setup with loaded values
                    ;;
                rename)
                    continue
                    ;;
            esac
        else
            CFG_INSTANCE_NAME="$name"
            return 0
        fi
    done
}

server_generate_config() {
    local config_file="${CONFIG_DIR}/${CFG_INSTANCE_NAME}.json"

    if is_root; then
        mkdir -p "$CONFIG_DIR"
        write_json_config "$config_file"
        chmod 640 "$config_file"
    else
        # Non-root: write to current directory
        config_file="${CFG_INSTANCE_NAME}.json"
        write_json_config "$config_file"
    fi

    echo "$config_file"
}

server_install_systemd_template() {
    if ! has_systemd; then
        return 1
    fi

    local template_path="${SYSTEMD_UNIT_DIR}/${SYSTEMD_TEMPLATE}"

    # Only install if missing
    if [[ -f "$template_path" ]]; then
        return 0
    fi

    local ss_server_path
    ss_server_path=$(command -v ss-server 2>/dev/null) || ss_server_path="/usr/local/bin/ss-server"

    local sd_ver
    sd_ver=$(systemd_version)

    if (( sd_ver >= 232 )); then
        cat > "$template_path" <<UNIT
[Unit]
Description=Shadowsocks-Libev Custom Server Service for %I
Documentation=man:ss-server(1)
After=network-online.target

[Service]
Type=simple
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
DynamicUser=true
LimitNOFILE=32768
ExecStart=${ss_server_path} -c /etc/shadowsocks-libev/%i.json

[Install]
WantedBy=multi-user.target
UNIT
    else
        cat > "$template_path" <<UNIT
[Unit]
Description=Shadowsocks-Libev Custom Server Service for %I
Documentation=man:ss-server(1)
After=network-online.target

[Service]
Type=simple
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
User=nobody
Group=nogroup
LimitNOFILE=32768
ExecStart=${ss_server_path} -c /etc/shadowsocks-libev/%i.json

[Install]
WantedBy=multi-user.target
UNIT
    fi

    systemctl daemon-reload
}

server_install_service() {
    local name="$1"
    local unit="shadowsocks-libev-server@${name}.service"

    server_install_systemd_template || {
        tui_msgbox "No systemd" "systemd not detected. Skipping service installation.\n\nStart manually:\n  ss-server -c ${CONFIG_DIR}/${name}.json"
        return 1
    }

    systemctl enable "$unit" 2>/dev/null
    systemctl restart "$unit" 2>/dev/null

    if systemctl is-active --quiet "$unit"; then
        return 0
    else
        return 1
    fi
}

server_show_summary() {
    local config_file="$1"
    local uri
    uri=$(generate_ss_uri "$CFG_METHOD" "$CFG_PASSWORD" "$CFG_SERVER" "$CFG_SERVER_PORT" "$CFG_PLUGIN" "$CFG_PLUGIN_OPTS")

    local service_status="(not installed)"
    if is_root && has_systemd; then
        local unit="shadowsocks-libev-server@${CFG_INSTANCE_NAME}.service"
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            service_status="active (running)"
        else
            service_status="inactive or failed"
        fi
    fi

    local summary=""
    summary+="Config file: ${config_file}\n"
    summary+="\n"
    summary+="Server:    ${CFG_SERVER}:${CFG_SERVER_PORT}\n"
    summary+="Method:    ${CFG_METHOD}\n"
    summary+="Password:  ${CFG_PASSWORD}\n"
    summary+="Mode:      ${CFG_MODE}\n"
    summary+="Fast Open: ${CFG_FAST_OPEN}\n"
    if [[ -n "$CFG_PLUGIN" ]]; then
        summary+="Plugin:    ${CFG_PLUGIN}\n"
        [[ -n "$CFG_PLUGIN_OPTS" ]] && summary+="Opts:      ${CFG_PLUGIN_OPTS}\n"
    fi
    summary+="Service:   ${service_status}\n"
    summary+="\n"
    summary+="ss:// URI (for client import):\n"
    summary+="${uri}\n"

    tui_msgbox "Server Setup Complete" "$summary"
}

server_setup() {
    while true; do
        server_ask_instance_name
        local rc=$?
        if [[ $rc -eq 1 ]]; then
            return  # user cancelled
        fi
        # rc=2 means config was loaded for editing, restart the flow
        # rc=0 means proceed

        server_ask_listen_address || return
        server_ask_port || return
        server_ask_method || return
        server_ask_password || return
        server_ask_timeout || return
        server_ask_mode || return
        server_ask_fast_open
        server_ask_plugin || return

        # Confirm before writing
        local confirm_msg=""
        confirm_msg+="Server:    ${CFG_SERVER}:${CFG_SERVER_PORT}\n"
        confirm_msg+="Method:    ${CFG_METHOD}\n"
        confirm_msg+="Mode:      ${CFG_MODE}\n"
        confirm_msg+="Fast Open: ${CFG_FAST_OPEN}\n"
        confirm_msg+="Instance:  ${CFG_INSTANCE_NAME}\n"
        [[ -n "$CFG_PLUGIN" ]] && confirm_msg+="Plugin:    ${CFG_PLUGIN}\n"

        if ! tui_yesno "Confirm" "Review your settings:\n\n${confirm_msg}\nProceed?"; then
            if tui_yesno "Restart" "Start over with new settings?"; then
                continue
            fi
            return
        fi

        break
    done

    # Generate config
    local config_file
    config_file=$(server_generate_config)

    # Install systemd service if root
    if is_root && has_systemd; then
        if tui_yesno "Systemd Service" "Install and start a systemd service for this instance?"; then
            if server_install_service "$CFG_INSTANCE_NAME"; then
                tui_msgbox "Service Started" "Service shadowsocks-libev-server@${CFG_INSTANCE_NAME} is now running."
            else
                tui_msgbox "Service Error" "Service failed to start.\n\nCheck: journalctl -u shadowsocks-libev-server@${CFG_INSTANCE_NAME} -n 20"
            fi
        fi
    fi

    # Show summary
    server_show_summary "$config_file"
}

###############################################################################
# Client Config Flow
###############################################################################

client_ask_server_address() {
    local addr
    while true; do
        addr=$(tui_inputbox "Server Address" "Enter the remote ss-server address (IP or hostname):" "$CFG_CLIENT_SERVER") || return 1
        if [[ -n "$addr" ]]; then
            CFG_CLIENT_SERVER="$addr"
            return 0
        fi
        tui_msgbox "Error" "Server address cannot be empty."
    done
}

client_ask_server_port() {
    local port
    while true; do
        port=$(tui_inputbox "Server Port" "Enter the remote ss-server port:" "$CFG_CLIENT_SERVER_PORT") || return 1
        if validate_port "$port"; then
            CFG_CLIENT_SERVER_PORT="$port"
            return 0
        fi
        tui_msgbox "Error" "Invalid port number. Must be 1-65535."
    done
}

client_ask_local_port() {
    local port
    while true; do
        port=$(tui_inputbox "Local Port" "Enter the local SOCKS5 listen port:" "$CFG_CLIENT_LOCAL_PORT") || return 1
        if validate_port "$port"; then
            CFG_CLIENT_LOCAL_PORT="$port"
            return 0
        fi
        tui_msgbox "Error" "Invalid port number. Must be 1-65535."
    done
}

client_ask_method() {
    local items=()
    local cipher
    for cipher in "${AEAD_CIPHERS[@]}"; do
        if [[ "$cipher" == "$CFG_CLIENT_METHOD" ]]; then
            items+=("$cipher" "" "ON")
        else
            items+=("$cipher" "" "OFF")
        fi
    done

    local method
    method=$(tui_radiolist "Encryption Method" "Select the cipher (must match server):" "${items[@]}") || return 1
    CFG_CLIENT_METHOD="$method"
}

client_ask_password() {
    local pass
    while true; do
        pass=$(tui_passwordbox "Password" "Enter the password (must match server):") || return 1
        if [[ -n "$pass" ]]; then
            CFG_CLIENT_PASSWORD="$pass"
            return 0
        fi
        tui_msgbox "Error" "Password cannot be empty."
    done
}

client_ask_plugin() {
    local installed
    installed=$(find_installed_plugins)

    local items=("none" "No plugin")
    local p
    for p in $installed; do
        items+=("$p" "$(command -v "$p" 2>/dev/null || echo "$p")")
    done
    items+=("custom" "Enter custom plugin path")

    local choice
    choice=$(tui_menu "SIP003 Plugin" "Select a plugin (must match server):" "${items[@]}") || return 1

    if [[ "$choice" == "none" ]]; then
        CFG_CLIENT_PLUGIN=""
        CFG_CLIENT_PLUGIN_OPTS=""
        return 0
    fi

    if [[ "$choice" == "custom" ]]; then
        local plugin_path
        plugin_path=$(tui_inputbox "Custom Plugin" "Enter the plugin binary name or full path:" "") || return 1
        if [[ -z "$plugin_path" ]]; then
            CFG_CLIENT_PLUGIN=""
            CFG_CLIENT_PLUGIN_OPTS=""
            return 0
        fi
        CFG_CLIENT_PLUGIN="$plugin_path"
    else
        CFG_CLIENT_PLUGIN="$choice"
    fi

    local opts
    opts=$(tui_inputbox "Plugin Options" "Enter plugin options (or leave empty):" "$CFG_CLIENT_PLUGIN_OPTS") || return 1
    CFG_CLIENT_PLUGIN_OPTS="$opts"
}

client_ask_output_path() {
    local default_path
    if is_root; then
        default_path="${CONFIG_DIR}/client.json"
    else
        default_path="${HOME}/ss-client.json"
    fi
    [[ -n "$CFG_CLIENT_OUTPUT" ]] && default_path="$CFG_CLIENT_OUTPUT"

    local path
    path=$(tui_inputbox "Output Path" "Where to save the client config:" "$default_path") || return 1
    CFG_CLIENT_OUTPUT="$path"
}

client_generate_config() {
    local outdir
    outdir=$(dirname "$CFG_CLIENT_OUTPUT")
    if [[ ! -d "$outdir" ]]; then
        mkdir -p "$outdir" 2>/dev/null || {
            tui_msgbox "Error" "Cannot create directory: ${outdir}"
            return 1
        }
    fi
    write_client_json_config "$CFG_CLIENT_OUTPUT"
    chmod 640 "$CFG_CLIENT_OUTPUT" 2>/dev/null || true
}

client_show_summary() {
    local uri
    uri=$(generate_ss_uri "$CFG_CLIENT_METHOD" "$CFG_CLIENT_PASSWORD" "$CFG_CLIENT_SERVER" "$CFG_CLIENT_SERVER_PORT" "$CFG_CLIENT_PLUGIN" "$CFG_CLIENT_PLUGIN_OPTS")

    local summary=""
    summary+="Config file: ${CFG_CLIENT_OUTPUT}\n"
    summary+="\n"
    summary+="Server:     ${CFG_CLIENT_SERVER}:${CFG_CLIENT_SERVER_PORT}\n"
    summary+="Local:      127.0.0.1:${CFG_CLIENT_LOCAL_PORT}\n"
    summary+="Method:     ${CFG_CLIENT_METHOD}\n"
    if [[ -n "$CFG_CLIENT_PLUGIN" ]]; then
        summary+="Plugin:     ${CFG_CLIENT_PLUGIN}\n"
        [[ -n "$CFG_CLIENT_PLUGIN_OPTS" ]] && summary+="Opts:       ${CFG_CLIENT_PLUGIN_OPTS}\n"
    fi
    summary+="\n"
    summary+="ss:// URI:\n${uri}\n"
    summary+="\n"
    summary+="Usage:\n  ss-local -c ${CFG_CLIENT_OUTPUT}\n"

    tui_msgbox "Client Config Complete" "$summary"
}

client_setup() {
    client_ask_server_address || return
    client_ask_server_port || return
    client_ask_local_port || return
    client_ask_method || return
    client_ask_password || return
    client_ask_plugin || return
    client_ask_output_path || return

    # Confirm
    local confirm_msg=""
    confirm_msg+="Server:  ${CFG_CLIENT_SERVER}:${CFG_CLIENT_SERVER_PORT}\n"
    confirm_msg+="Local:   127.0.0.1:${CFG_CLIENT_LOCAL_PORT}\n"
    confirm_msg+="Method:  ${CFG_CLIENT_METHOD}\n"
    confirm_msg+="Output:  ${CFG_CLIENT_OUTPUT}\n"
    [[ -n "$CFG_CLIENT_PLUGIN" ]] && confirm_msg+="Plugin:  ${CFG_CLIENT_PLUGIN}\n"

    if ! tui_yesno "Confirm" "Review your settings:\n\n${confirm_msg}\nProceed?"; then
        return
    fi

    client_generate_config || return
    client_show_summary
}

###############################################################################
# Plugin Installation Flow
###############################################################################

plugin_download_github_release() {
    local repo="$1" binary_name="$2"
    local os arch api_url assets_json download_url asset_name

    os=$(detect_os)
    arch=$(detect_arch)

    if ! command -v curl >/dev/null 2>&1; then
        tui_msgbox "Error" "curl is required for downloading plugins."
        return 1
    fi

    api_url="https://api.github.com/repos/${repo}/releases/latest"

    tui_msgbox "Downloading" "Fetching latest release info from:\n${repo}\n\nPlease wait..."

    assets_json=$(curl -sS --connect-timeout 15 --max-time 30 "$api_url") || {
        tui_msgbox "Error" "Failed to fetch release info from GitHub.\n\nCheck your network connection."
        return 1
    }

    # Find matching asset URL -- look for os and arch in filename
    download_url=""
    # Try common naming patterns
    local patterns=()
    patterns+=("${os}-${arch}")
    patterns+=("${os}_${arch}")
    # Map arch names for different projects
    case "$arch" in
        amd64) patterns+=("${os}-amd64" "${os}_amd64" "${os}-x86_64" "${os}_x86_64" "linux-64") ;;
        arm64) patterns+=("${os}-arm64" "${os}_arm64" "${os}-aarch64" "${os}_aarch64") ;;
    esac

    local p
    for p in "${patterns[@]}"; do
        download_url=$(echo "$assets_json" | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*'"$p"'[^"]*"' | head -1 | sed 's/.*"\(http[^"]*\)".*/\1/')
        [[ -n "$download_url" ]] && break
    done

    if [[ -z "$download_url" ]]; then
        tui_msgbox "Error" "Could not find a matching release for ${os}-${arch}.\n\nYou may need to build from source or download manually."
        return 1
    fi

    asset_name=$(basename "$download_url")

    TMPDIR_CLEANUP=$(mktemp -d)
    local tmpdir="$TMPDIR_CLEANUP"

    tui_msgbox "Downloading" "Downloading:\n${asset_name}\n\nThis may take a moment..."

    if ! curl -sSL --connect-timeout 15 --max-time 120 -o "${tmpdir}/${asset_name}" "$download_url"; then
        tui_msgbox "Error" "Download failed."
        return 1
    fi

    # Extract based on file type
    local extract_dir="${tmpdir}/extract"
    mkdir -p "$extract_dir"

    case "$asset_name" in
        *.tar.gz|*.tgz)
            tar xzf "${tmpdir}/${asset_name}" -C "$extract_dir" || {
                tui_msgbox "Error" "Failed to extract archive."
                return 1
            }
            ;;
        *.zip)
            unzip -q "${tmpdir}/${asset_name}" -d "$extract_dir" || {
                tui_msgbox "Error" "Failed to extract archive."
                return 1
            }
            ;;
        *)
            # Assume it's the binary itself
            cp "${tmpdir}/${asset_name}" "${extract_dir}/${binary_name}"
            chmod +x "${extract_dir}/${binary_name}"
            ;;
    esac

    # Find the binary
    local found_binary=""
    found_binary=$(find "$extract_dir" -name "$binary_name" -type f 2>/dev/null | head -1)

    # Some plugins have different names in the archive
    if [[ -z "$found_binary" ]]; then
        # Try finding any executable
        found_binary=$(find "$extract_dir" -type f -executable 2>/dev/null | head -1)
    fi
    if [[ -z "$found_binary" ]]; then
        found_binary=$(find "$extract_dir" -type f -name "${binary_name}*" 2>/dev/null | head -1)
    fi

    if [[ -z "$found_binary" ]]; then
        tui_msgbox "Error" "Could not find '${binary_name}' in the downloaded archive.\n\nContents of archive:\n$(ls -la "$extract_dir" 2>/dev/null)"
        return 1
    fi

    chmod +x "$found_binary"
    cp "$found_binary" "/usr/local/bin/${binary_name}"

    if command -v "$binary_name" >/dev/null 2>&1; then
        tui_msgbox "Success" "${binary_name} installed to /usr/local/bin/${binary_name}"
        return 0
    else
        tui_msgbox "Warning" "Installed to /usr/local/bin/${binary_name} but it was not found in PATH."
        return 0
    fi
}

plugin_install_simple_obfs() {
    local distro
    distro=$(detect_distro)

    local method
    method=$(tui_menu "Install simple-obfs" "Choose installation method:" \
        "package" "Install via package manager (if available)" \
        "source" "Build from source (requires git, build tools)") || return 1

    if [[ "$method" == "package" ]]; then
        case "$distro" in
            ubuntu|debian)
                apt-get update && apt-get install -y simple-obfs && {
                    tui_msgbox "Success" "simple-obfs installed via apt."
                    return 0
                }
                tui_msgbox "Notice" "Package not available. Trying source build..."
                ;;
            *)
                tui_msgbox "Notice" "No package available for ${distro}. Building from source..."
                ;;
        esac
    fi

    # Build from source
    if ! command -v git >/dev/null 2>&1; then
        tui_msgbox "Error" "git is required to build from source."
        return 1
    fi
    if ! command -v make >/dev/null 2>&1; then
        tui_msgbox "Error" "make is required to build from source."
        return 1
    fi

    TMPDIR_CLEANUP=$(mktemp -d)
    local tmpdir="$TMPDIR_CLEANUP"

    tui_msgbox "Building" "Cloning and building simple-obfs...\nThis may take a few minutes."

    (
        cd "$tmpdir"
        git clone https://github.com/shadowsocks/simple-obfs.git
        cd simple-obfs
        git submodule update --init --recursive
        ./autogen.sh
        ./configure
        make
        make install
    ) || {
        tui_msgbox "Error" "Build failed. Check that build dependencies are installed:\n  autoconf, automake, libtool, libev-dev"
        return 1
    }

    if command -v obfs-local >/dev/null 2>&1; then
        tui_msgbox "Success" "simple-obfs built and installed.\nBinaries: obfs-local, obfs-server"
    else
        tui_msgbox "Warning" "Build completed but obfs-local not found in PATH."
    fi
}

plugin_install_custom() {
    local path
    path=$(tui_inputbox "Custom Plugin" "Enter the full path to the plugin binary:" "") || return 1

    if [[ -z "$path" ]]; then
        return 1
    fi

    if [[ ! -f "$path" ]]; then
        tui_msgbox "Error" "File not found: ${path}"
        return 1
    fi

    if [[ ! -x "$path" ]]; then
        chmod +x "$path"
    fi

    local name
    name=$(basename "$path")

    if tui_yesno "Symlink" "Create a symlink in /usr/local/bin/${name}?"; then
        ln -sf "$path" "/usr/local/bin/${name}"
        tui_msgbox "Done" "Symlinked ${path} → /usr/local/bin/${name}"
    else
        tui_msgbox "Done" "Plugin at ${path} is ready to use.\nSpecify the full path when configuring."
    fi
}

plugin_install() {
    if ! is_root; then
        tui_msgbox "Root Required" "Plugin installation requires root privileges.\n\nRe-run with sudo."
        return
    fi

    local items=()
    local p
    for p in "${KNOWN_PLUGINS[@]}"; do
        local status="not installed"
        if command -v "$p" >/dev/null 2>&1; then
            status="installed"
        fi
        items+=("$p" "$(plugin_repo "$p") (${status})")
    done
    items+=("custom" "Install a custom binary")

    local choice
    choice=$(tui_menu "Install Plugin" "Select a plugin to install:" "${items[@]}") || return

    case "$choice" in
        simple-obfs)
            plugin_install_simple_obfs
            ;;
        v2ray-plugin)
            plugin_download_github_release "$(plugin_repo v2ray-plugin)" "v2ray-plugin"
            ;;
        xray-plugin)
            plugin_download_github_release "$(plugin_repo xray-plugin)" "xray-plugin"
            ;;
        kcptun)
            plugin_download_github_release "$(plugin_repo kcptun)" "kcptun-client"
            ;;
        custom)
            plugin_install_custom
            ;;
    esac
}

###############################################################################
# Service Management
###############################################################################

service_list_instances() {
    local instances=()

    # Scan config files
    if [[ -d "$CONFIG_DIR" ]]; then
        local f name
        for f in "${CONFIG_DIR}"/*.json; do
            [[ -f "$f" ]] || continue
            name=$(basename "$f" .json)
            local status="no service"
            local unit="shadowsocks-libev-server@${name}.service"
            if has_systemd; then
                if systemctl is-active --quiet "$unit" 2>/dev/null; then
                    status="running"
                elif systemctl is-enabled --quiet "$unit" 2>/dev/null; then
                    status="stopped (enabled)"
                fi
            fi
            instances+=("$name" "${status}")
        done
    fi

    if [[ ${#instances[@]} -eq 0 ]]; then
        tui_msgbox "No Instances" "No config files found in ${CONFIG_DIR}/"
        return 1
    fi

    local choice
    choice=$(tui_menu "Instances" "Select an instance:" "${instances[@]}") || return 1
    echo "$choice"
}

service_action_menu() {
    local name="$1"
    local unit="shadowsocks-libev-server@${name}.service"

    while true; do
        local action
        action=$(tui_menu "Manage: ${name}" "Select an action:" \
            "status" "View service status" \
            "start" "Start the service" \
            "stop" "Stop the service" \
            "restart" "Restart the service" \
            "enable" "Enable on boot" \
            "disable" "Disable on boot" \
            "logs" "View recent logs" \
            "back" "Return to instance list") || return

        case "$action" in
            status)
                local st
                st=$(systemctl status "$unit" 2>&1 || true)
                tui_msgbox "Status: ${name}" "$st"
                ;;
            start)
                systemctl start "$unit" 2>&1 && \
                    tui_msgbox "Started" "Service ${unit} started." || \
                    tui_msgbox "Error" "Failed to start ${unit}."
                ;;
            stop)
                systemctl stop "$unit" 2>&1 && \
                    tui_msgbox "Stopped" "Service ${unit} stopped." || \
                    tui_msgbox "Error" "Failed to stop ${unit}."
                ;;
            restart)
                systemctl restart "$unit" 2>&1 && \
                    tui_msgbox "Restarted" "Service ${unit} restarted." || \
                    tui_msgbox "Error" "Failed to restart ${unit}."
                ;;
            enable)
                systemctl enable "$unit" 2>&1 && \
                    tui_msgbox "Enabled" "Service ${unit} enabled on boot." || \
                    tui_msgbox "Error" "Failed to enable ${unit}."
                ;;
            disable)
                systemctl disable "$unit" 2>&1 && \
                    tui_msgbox "Disabled" "Service ${unit} disabled." || \
                    tui_msgbox "Error" "Failed to disable ${unit}."
                ;;
            logs)
                local logs
                logs=$(journalctl -u "$unit" -n 50 --no-pager 2>&1 || echo "(no logs available)")
                tui_msgbox "Logs: ${name}" "$logs"
                ;;
            back)
                return
                ;;
        esac
    done
}

service_manage() {
    if ! is_root; then
        tui_msgbox "Root Required" "Service management requires root privileges.\n\nRe-run with sudo."
        return
    fi

    if ! has_systemd; then
        tui_msgbox "No systemd" "systemd was not detected on this system.\n\nService management is not available."
        return
    fi

    while true; do
        local instance
        instance=$(service_list_instances) || return
        service_action_menu "$instance"
    done
}

###############################################################################
# Main Menu
###############################################################################

main_menu() {
    while true; do
        local choice
        choice=$(tui_menu "ss-setup v${SS_SETUP_VERSION}" "shadowsocks-libev setup tool" \
            "server" "Setup ss-server (generate config + service)" \
            "client" "Generate ss-local client config" \
            "plugin" "Install a SIP003 plugin" \
            "service" "Manage running services" \
            "exit" "Exit") || break

        case "$choice" in
            server)  server_setup ;;
            client)  client_setup ;;
            plugin)  plugin_install ;;
            service) service_manage ;;
            exit)    break ;;
        esac
    done
}

###############################################################################
# Entry Point
###############################################################################

main() {
    # Non-interactive check
    if [[ ! -t 0 ]]; then
        echo "Error: ss-setup requires an interactive terminal." >&2
        echo "Usage: ss-setup" >&2
        exit 1
    fi

    detect_tui_backend
    check_root || true  # warn but continue
    main_menu

    echo "Goodbye."
}

# Only run main when executed directly (not when sourced for testing)
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
