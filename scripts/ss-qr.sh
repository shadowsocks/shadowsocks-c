#!/usr/bin/env bash
config_file="/etc/shadowsocks-libev/config.json"
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#
# Generate QR Code for Shadowsocks Windows, OSX, Android and iOS clients
# (use on server with installed Shadowsocks-libev)
#
# This script is mostly borrowed from the script:
# Auto Install Shadowsocks Server for CentOS/Debian/Ubuntu
# by teddysun
# (https://github.com/teddysun/shadowsocks_install)
#

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'


function call() {       # var=func [args ...]
  REPLY=; "${1#*=}" "${@:2}"; eval "${1%%=*}=\$REPLY; return $?"
}

get_json_value() {
    if [ "$(command -v python3)" = "" ]; then
        echo ""
        echo -e "${red}Error: ${plain}There is no 'python3' command in the system"
        return 1
    fi
    REPLY="$(echo "$1" | python3 -c "import sys, json; print(json.load(sys.stdin)['$2'])")"
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z ${ipv6} ] && return 1 || return 0
}

qr_generate_libev(){
    if [ "$(command -v qrencode)" = "" ]; then
        echo ""
        echo -e "${red}Error: ${plain}There is no 'qrencode' command in the system"
        return 1
    fi
    local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
    local qr_code="ss://${tmp}"
    local cur_dir=$(pwd)
    echo
    echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
    echo -e "${green} ${qr_code} ${plain}"
    echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_libev_qr.png
    echo "Your QR Code has been saved as a PNG file path:"
    echo -e "${green} ${cur_dir}/shadowsocks_libev_qr.png ${plain}"
}


config_str=$(cat "$config_file")

call shadowsockscipher=get_json_value "$config_str" "method"
if [ $? -eq 1 ]; then
    exit 1
fi
call shadowsockspwd=get_json_value "$config_str" "password"
call shadowsocksport=get_json_value "$config_str" "server_port"


qr_generate_libev
if [ $? -eq 1 ]; then
    exit 1
fi
