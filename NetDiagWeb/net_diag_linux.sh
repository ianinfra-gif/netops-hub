#!/bin/bash

# ==========================================
# Linux Network Diagnostic Tool
# ==========================================

TARGET_WAN_IP="1.1.1.1"
TARGET_DNS_DOMAIN="google.com"
TEST_MTU_SIZE=1200
TIMEOUT_PING=1
TIMEOUT_CURL=3
TIMEOUT_NC=2
SERVER_URL=""

while [ $# -gt 0 ]; do
    case "$1" in
        --server-url) SERVER_URL="$2"; shift 2 ;;
        *) echo "Usage: $0 [--server-url http://server:8000]"; exit 2 ;;
    esac
done

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

ERRORS=()
LOG_TEXT=""
START_SECONDS=0

append_log()    { LOG_TEXT+="$1\n"; }

print_header()  { 
    local HOST_NAME=$(hostname -s)
    local OS_NAME=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    
    echo -e "${BOLD}Linux Network Diagnostic Tool${NC}" 
    echo -e "Host: $HOST_NAME | OS: ${OS_NAME:-Linux}"
    echo -e "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "----------------------------------------"
    
    append_log "Linux Network Diagnostic Tool"
    append_log "Host: $HOST_NAME | OS: ${OS_NAME:-Linux}"
    append_log "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
    append_log "----------------------------------------"
    
    START_SECONDS=$(date +%s)
}

print_success() { echo -e " [${GREEN}OK${NC}]   $1 : $2"; append_log "[OK]   $1 : $2"; }
print_error()   { echo -e " [${RED}FAIL${NC}] $1 : $2"; append_log "[FAIL] $1 : $2"; }
print_warn()    { echo -e " [${YELLOW}WARN${NC}] $1 : $2"; append_log "[WARN] $1 : $2"; }
print_info()    { echo -e " [${CYAN}INFO${NC}] $1 : $2"; append_log "[INFO] $1 : $2"; }
add_error()     { ERRORS+=("$1"); append_log "       -> 警示: $1"; }

check_ipv4_status() {
    local DEF_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n 1)
    local LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$LOCAL_IP" ] && LOCAL_IP=$(ip -4 addr show "$DEF_IFACE" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v '127.0.0.1' | head -n 1)

    if [ -n "$LOCAL_IP" ]; then
        print_success "本機網卡狀態" "${BOLD}${DEF_IFACE:-eth0}${NC} (IPv4: $LOCAL_IP)"
        if [[ "$LOCAL_IP" == 169.254.* ]]; then
            print_error "網卡 IP 異常" "取得 Self-Assigned IP"
            add_error "網卡取得 169.254.x.x 虛擬 IP，DHCP 發放失敗或驗證錯誤。"
        fi
    else
        print_error "本機網卡狀態" "未連線到任何網路介面"
        add_error "實體網路未連線，請確認實體線路或 Wi-Fi。"
    fi
}

check_wifi_radar() {
    if command -v nmcli >/dev/null 2>&1; then
        local WIFI_INFO=$(nmcli -t -f active,ssid,bssid,signal,rate dev wifi 2>/dev/null | grep '^yes')
        if [ -n "$WIFI_INFO" ]; then
            local SSID=$(echo "$WIFI_INFO" | cut -d: -f2)
            local BSSID=$(echo "$WIFI_INFO" | cut -d: -f3..8)
            local SIGNAL=$(echo "$WIFI_INFO" | cut -d: -f9)
            local RATE=$(echo "$WIFI_INFO" | cut -d: -f10)
            print_info "無線網路探測" "SSID: $SSID (BSSID: $BSSID)"
            print_info "無線網路品質" "強度: ${SIGNAL}% | 速率: ${RATE}"
        fi
    fi
}

check_ipv6_conflict() {
    local IPV6_GW=$(ip -6 route show default 2>/dev/null | awk '/default/ {print $3}')
    if [ -n "$IPV6_GW" ]; then
        if curl --max-time $TIMEOUT_CURL -6 -sI https://$TARGET_DNS_DOMAIN >/dev/null 2>&1; then
            print_success "六號協定路由" "支援且連通"
        else
            print_warn "六號協定路由" "存在路由但無法連通 (封包遺失)"
            add_error "發現 IPv6 雙堆疊衝突，易導致連線逾時，建議暫時關閉 IPv6。"
        fi
    fi
}

check_gateway() {
    local GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3}')
    if [ -n "$GATEWAY" ]; then
        if ping -c 1 -W $TIMEOUT_PING "$GATEWAY" >/dev/null 2>&1; then
            print_success "預設閘道狀態" "${BOLD}$GATEWAY${NC} (連線正常)"
        else
            print_error "預設閘道狀態" "${BOLD}$GATEWAY${NC} (無法 Ping 通)"
            add_error "無法連線到本地路由器 ($GATEWAY)，請檢查內部網段狀態。"
        fi
    else
        print_warn "預設閘道狀態" "無預設 Gateway"
    fi
}

check_arp_gateway() {
    local GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3}')
    if [ -n "$GATEWAY" ]; then
        local MAC=$(ip neighbor show "$GATEWAY" 2>/dev/null | awk '{print $5}')
        [ -z "$MAC" ] && MAC=$(arp -n "$GATEWAY" 2>/dev/null | awk '{print $4}')

        if [[ "$MAC" == "(incomplete)" || -z "$MAC" ]]; then
            print_warn "閘道位址解析" "無法解析閘道 $GATEWAY 的 MAC 位址"
            add_error "ARP 解析失敗，內網可能發生 IP 衝突或 ARP 欺騙。"
        else
            print_success "閘道位址解析" "Gateway MAC 正常 ($MAC)"
        fi
    fi
}

check_vpn_and_mtu() {
    local VPN_DEV=$(ip link show 2>/dev/null | grep -E 'tun[0-9]+|tap[0-9]+|ppp[0-9]+' | awk -F': ' '{print $2}' | head -n 1)
    if [ -n "$VPN_DEV" ]; then
        local VPN_IP=$(ip -4 addr show "$VPN_DEV" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        print_success "虛擬通道狀態" "介面 ${BOLD}$VPN_DEV${NC} (IP: ${VPN_IP:-N/A})"
        
        if ping -M do -s $TEST_MTU_SIZE -c 1 -W $TIMEOUT_PING $TARGET_WAN_IP >/dev/null 2>&1; then
            print_success "傳輸單元狀態" "隧道寬度正常"
        else
            print_info "傳輸單元狀態" "隧道較窄 (系統已自動適應)"
        fi
    else
        print_success "虛擬通道狀態" "介面 ${BOLD}N/A${NC} (未開啟 VPN)"
        print_success "傳輸單元狀態" "傳輸正常"
    fi
}

check_wan_and_firewall() {
    if ping -c 1 -W $TIMEOUT_PING $TARGET_WAN_IP >/dev/null 2>&1; then
        print_success "網際網路直連" "$TARGET_WAN_IP (ICMP 通暢)"
        if (nc -z -w $TIMEOUT_NC $TARGET_WAN_IP 443 >/dev/null 2>&1 || curl -sI --max-time $TIMEOUT_CURL https://$TARGET_WAN_IP >/dev/null 2>&1); then
            print_success "防火牆通訊埠" "Port 80/443 未被封鎖"
        else
            print_error "防火牆通訊埠" "TCP 連線被拒絕"
            add_error "ICMP 正常但 TCP 通訊埠被封鎖，請檢查防火牆或企業出口策略。"
        fi
    else
        print_error "網際網路直連" "$TARGET_WAN_IP (斷線/封鎖)"
        local TRACE_RES=$(traceroute -n -m 4 -w 1 -q 1 $TARGET_WAN_IP 2>/dev/null | tail -n +2)
        add_error "外網斷線。前 4 個路由節點狀態：\n$TRACE_RES"
    fi
}

check_captive_portal() {
    local PORTAL_TEST=$(curl -s --max-time $TIMEOUT_CURL http://connectivitycheck.gstatic.com/generate_204 2>&1)
    if [ -z "$PORTAL_TEST" ]; then
        print_success "網路通行驗證" "無攔截 (未被驗證牆阻擋)"
    else
        print_warn "網路通行驗證" "偵測到 Captive Portal"
        add_error "連線被公共 Wi-Fi 登入頁面攔截，請完成網頁驗證。"
    fi
}

check_dns_and_ssl() {
    local DNS_SERVERS=$(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -n 1)
    if (nc -z -w $TIMEOUT_NC $TARGET_DNS_DOMAIN 443 >/dev/null 2>&1 || curl -sI --max-time $TIMEOUT_CURL https://$TARGET_DNS_DOMAIN >/dev/null 2>&1); then
        print_success "網域名稱解析" "$TARGET_DNS_DOMAIN (解析正常)"
        if ! curl -sI --max-time $TIMEOUT_CURL https://$TARGET_DNS_DOMAIN >/dev/null 2>&1; then
            print_warn "傳輸加密憑證" "驗證失敗 (時間錯誤)"
            add_error "HTTPS 憑證驗證失敗，請檢查 NTP 系統時間是否準確。"
        fi
    else
        print_error "網域名稱解析" "失敗 (使用的 DNS: ${DNS_SERVERS:-未知})"
        add_error "網址無法解析。目前 DNS ($DNS_SERVERS) 無回應或遭污染。"
    fi
}

check_proxy() {
    if [ -n "$http_proxy" ] || [ -n "$HTTP_PROXY" ]; then
        print_warn "系統代理設定" "已開啟 (${http_proxy:-$HTTP_PROXY})"
        add_error "偵測到本機 HTTP Proxy，若代理失效將導致無法上網。"
    fi
}

check_speedtest() {
    local GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -n 1)
    if [ -n "$GATEWAY" ]; then
        local RTT=$(ping -c 3 -i 0.2 "$GATEWAY" 2>/dev/null | awk -F'/' '/rtt|round-trip/ {print $5}')
        [ -n "$RTT" ] && print_success "對內網路品質" "閘道 $GATEWAY 延遲: ${RTT} ms"
    fi

    local TMP_PING="/tmp/wan_ping_$$.tmp"
    ping -c 5 -i 0.5 1.1.1.1 > "$TMP_PING" 2>&1 &
    local PING_PID=$!

    local B_BYTES_DL=$(curl -s -w "%{speed_download}" -o /dev/null "https://speed.cloudflare.com/__down?bytes=10000000" --max-time 5 2>/dev/null)
    local B_BYTES_UL=$(curl -s -w "%{speed_upload}" -o /dev/null -F "file=@/dev/zero" "https://speed.cloudflare.com/__up" --max-time 5 2>/dev/null)

    wait $PING_PID 2>/dev/null

    local LOADED_RTT=$(awk -F'/' '/rtt|round-trip/ {print $5}' "$TMP_PING" 2>/dev/null | cut -d. -f1)
    rm -f "$TMP_PING"

    local RATING="普通 (一般順暢)"
    if [ -n "$LOADED_RTT" ] && [ "$LOADED_RTT" -eq "$LOADED_RTT" ] 2>/dev/null; then
        if [ "$LOADED_RTT" -lt 25 ]; then RATING="優良 (極低延遲)"
        elif [ "$LOADED_RTT" -gt 80 ]; then RATING="不佳 (滿載易卡頓)"
        fi
    fi

    local DL_MBPS="0.00"
    local UL_MBPS="0.00"
    [ -n "$B_BYTES_DL" ] && [ "$B_BYTES_DL" != "0" ] && DL_MBPS=$(awk -v b="$B_BYTES_DL" 'BEGIN {printf "%.2f", (b * 8) / 1000000}')
    [ -n "$B_BYTES_UL" ] && [ "$B_BYTES_UL" != "0" ] && UL_MBPS=$(awk -v b="$B_BYTES_UL" 'BEGIN {printf "%.2f", (b * 8) / 1000000}')

    if [ "$DL_MBPS" != "0.00" ]; then
        print_success "對外頻寬測試" "下行: ${DL_MBPS} Mbps | 上行: ${UL_MBPS} Mbps | 評級: $RATING"
    else
        print_warn "對外頻寬測試" "測速逾時或遭網路限制"
    fi
}

print_summary() {
    echo -e "----------------------------------------"
    append_log "----------------------------------------"
    
    if [ ${#ERRORS[@]} -eq 0 ]; then
        echo -e "${GREEN}${BOLD}[診斷結論] 網路狀態正常，未檢測到連線異常。${NC}"
        append_log "[診斷結論] 網路狀態正常，未檢測到連線異常。"
    else
        echo -e "${RED}${BOLD}[診斷結論] 發現連線異常，請參考以下警示項目：${NC}"
        append_log "[診斷結論] 發現連線異常，請參考以下警示項目："
        for err in "${ERRORS[@]}"; do
            echo -e " $err"
            append_log " $err"
        done
    fi
    echo -e "----------------------------------------"
    append_log "----------------------------------------"
    
    local IDENTIFIER="${CLIENT_IP:-127.0.0.1}"
    local LOG_DIR="$(dirname "$0")/logs"
    mkdir -p "$LOG_DIR"
    local LOG_FILE="$LOG_DIR/NetDiag_${IDENTIFIER}_$(date +%Y%m%d_%H%M%S).log"
    
    echo -e "$LOG_TEXT" | sed 's/\x1b\[[0-9;]*m//g' > "$LOG_FILE"
    
    local END_SECONDS=$(date +%s)
    local DURATION=$((END_SECONDS - START_SECONDS))
    
    echo -e " [INFO] 檢測日誌已存至: logs/$(basename "$LOG_FILE")"
    echo -e " [INFO] 總執行耗時: ${DURATION} 秒"
    if [ -n "$SERVER_URL" ]; then
        if curl -fsS --max-time 10 --data-binary "@$LOG_FILE" "${SERVER_URL%/}/upload_log" >/dev/null; then
            echo -e " [INFO] 檢測報告已回傳至控制臺"
        else
            echo -e " [WARN] 無法回傳報告，請確認控制臺網址與連線狀態"
        fi
    fi
}

# Main
print_header
check_ipv4_status
check_wifi_radar
check_ipv6_conflict
check_gateway
check_arp_gateway
check_vpn_and_mtu
check_wan_and_firewall
check_captive_portal
check_dns_and_ssl
check_proxy
check_speedtest
print_summary
