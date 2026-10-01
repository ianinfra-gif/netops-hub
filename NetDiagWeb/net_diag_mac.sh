#!/bin/zsh

# ==========================================
# macOS Network Diagnostic Tool
# ==========================================

TARGET_WAN_IP="1.1.1.1"
TARGET_DNS_DOMAIN="google.com"
TEST_MTU_SIZE=1200
TIMEOUT_PING=1000
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

append_log()    { LOG_TEXT+="$1\n" }

print_header()  { 
    local HOST_NAME=$(hostname -s)
    local OS_VER=$(sw_vers -productVersion)
    
    echo -e "${BOLD}macOS Network Diagnostic Tool${NC}" 
    echo -e "Host: $HOST_NAME | OS: macOS $OS_VER"
    echo -e "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "----------------------------------------"
    
    append_log "macOS Network Diagnostic Tool"
    append_log "Host: $HOST_NAME | macOS $OS_VER"
    append_log "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
    append_log "----------------------------------------"
    
    START_SECONDS=$(date +%s)
}

print_success() { echo -e " [${GREEN}OK${NC}]   $1 : $2"; append_log "[OK]   $1 : $2"; }
print_error()   { echo -e " [${RED}FAIL${NC}] $1 : $2"; append_log "[FAIL] $1 : $2"; }
print_warn()    { echo -e " [${YELLOW}WARN${NC}] $1 : $2"; append_log "[WARN] $1 : $2"; }
print_info()    { echo -e " [${CYAN}INFO${NC}] $1 : $2"; append_log "[INFO] $1 : $2"; }
add_error()     { ERRORS+=("$1"); append_log "       -> 警示: $1"; }

check_dependencies() {
    for cmd in awk grep ping ifconfig route scutil curl nc traceroute arp; do
        if ! command -v $cmd >/dev/null 2>&1; then
            echo -e "${RED}[FATAL] 遺失系統核心工具 $cmd，無法執行診斷。${NC}"
            exit 1
        fi
    done
}

check_ipv4_status() {
    local DEF_DEV=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
    local LOCAL_IP=$(ifconfig "$DEF_DEV" 2>/dev/null | awk '/inet / {print $2}')

    if [ -n "$DEF_DEV" ] && [ -n "$LOCAL_IP" ]; then
        print_success "本機網卡狀態" "${BOLD}$DEF_DEV${NC} (IPv4: $LOCAL_IP)"
        if [[ "$LOCAL_IP" == 169.254.* ]]; then
            print_error "網卡位址異常" "取得 Self-Assigned IP"
            add_error "網卡取得 169.254.x.x 虛擬 IP，DHCP 發放失敗或驗證錯誤。"
        fi
    else
        print_error "本機網卡狀態" "未連線到任何網路介面"
        add_error "實體網路未連線，請確認實體線路或 Wi-Fi。"
    fi
}

check_wifi_radar() {
    local AIRPORT_CMD="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if [ -x "$AIRPORT_CMD" ]; then
        local WIFI_INFO=$("$AIRPORT_CMD" -I 2>/dev/null)
        local SSID=$(echo "$WIFI_INFO" | awk -F': ' '/ SSID/ {print $2}')
        if [ -n "$SSID" ] && [ "$SSID" != "Off" ]; then
            local BSSID=$(echo "$WIFI_INFO" | awk -F': ' '/ BSSID/ {print $2}')
            local RSSI=$(echo "$WIFI_INFO" | awk -F': ' '/ agrCtlRSSI/ {print $2}')
            local NOISE=$(echo "$WIFI_INFO" | awk -F': ' '/ agrCtlNoise/ {print $2}')
            local TX_RATE=$(echo "$WIFI_INFO" | awk -F': ' '/ lastTxRate/ {print $2}')
            
            print_info "無線網路探測" "SSID: $SSID (BSSID: $BSSID)"
            print_info "無線網路品質" "強度: ${RSSI}dBm | 雜訊: ${NOISE}dBm | 速率: ${TX_RATE}Mbps"
        fi
    fi
}

check_ipv6_conflict() {
    local IPV6_GW=$(route -n get -inet6 default 2>/dev/null | awk '/gateway:/ {print $2}')
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
    local GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
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
    local GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
    if [ -n "$GATEWAY" ]; then
        local MAC=$(arp -n "$GATEWAY" 2>/dev/null | awk '{print $4}')
        if [[ "$MAC" == "(incomplete)" ]] || [[ -z "$MAC" ]]; then
            print_warn "閘道位址解析" "無法解析閘道 $GATEWAY 的 MAC 位址"
            add_error "ARP 解析失敗，內網可能發生 IP 衝突或 ARP 欺騙。"
        else
            print_success "閘道位址解析" "Gateway MAC 正常 ($MAC)"
        fi
    fi
}

check_vpn_and_mtu() {
    local VPN_DEV=$(ifconfig | grep -E '^utun[0-9]+|^ppp[0-9]+' | cut -d: -f1 | head -n 1)
    if [ -n "$VPN_DEV" ]; then
        local VPN_IP=$(ifconfig "$VPN_DEV" 2>/dev/null | awk '/inet / {print $2}')
        print_success "虛擬通道狀態" "介面 ${BOLD}$VPN_DEV${NC} (IP: ${VPN_IP:-N/A})"
        
        if ping -c 1 -W $TIMEOUT_PING $TARGET_WAN_IP >/dev/null 2>&1; then
            if ping -D -s $TEST_MTU_SIZE -c 1 -W $TIMEOUT_PING $TARGET_WAN_IP >/dev/null 2>&1; then
                print_success "傳輸單元狀態" "隧道寬度正常"
            else
                print_info "傳輸單元狀態" "隧道較窄 (系統已自動適應)"
            fi
        fi
    else
        print_success "虛擬通道狀態" "介面 ${BOLD}N/A${NC} (未開啟 VPN)"
        print_success "傳輸單元狀態" "傳輸正常"
    fi
}

check_wan_and_firewall() {
    if ping -c 1 -W $TIMEOUT_PING $TARGET_WAN_IP >/dev/null 2>&1; then
        print_success "網際網路直連" "$TARGET_WAN_IP (ICMP 通暢)"
        
        if nc -G $TIMEOUT_NC -zv $TARGET_WAN_IP 443 >/dev/null 2>&1 && nc -G $TIMEOUT_NC -zv $TARGET_WAN_IP 80 >/dev/null 2>&1; then
            print_success "防火牆通訊埠" "Port 80/443 未被封鎖"
        else
            print_error "防火牆通訊埠" "TCP 連線被拒絕"
            add_error "ICMP 正常但 TCP 通訊埠被封鎖，請檢查 pf 防火牆或企業出口策略。"
        fi
    else
        print_error "網際網路直連" "$TARGET_WAN_IP (斷線/封鎖)"
        print_info "啟動節點追蹤" "正在尋找斷線點 (Tracing Hops...)"
        local TRACE_RES=$(traceroute -n -m 4 -w 1 -q 1 $TARGET_WAN_IP 2>/dev/null | tail -n +2)
        add_error "外網斷線。前 4 個路由節點狀態：\n$TRACE_RES"
    fi
}

check_captive_portal() {
    local PORTAL_TEST=$(curl -s --max-time $TIMEOUT_CURL http://captive.apple.com)
    if echo "$PORTAL_TEST" | grep -q "Success"; then
        print_success "網路通行驗證" "無攔截 (未被驗證牆阻擋)"
    elif [ -n "$PORTAL_TEST" ]; then
        print_warn "網路通行驗證" "偵測到 Captive Portal"
        add_error "連線被公共 Wi-Fi 登入頁面攔截，請完成網頁驗證。"
    fi
}

check_dns_and_ssl() {
    local DNS_SERVERS=$(scutil --dns | awk '/nameserver\[0\]/ {print $3}' | head -n 1)
    if nc -G $TIMEOUT_NC -zv $TARGET_DNS_DOMAIN 443 >/dev/null 2>&1; then
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
    local HTTP_PROXY=$(scutil --proxy | awk '/HTTPEnable/ {print $3}')
    if [ "$HTTP_PROXY" = "1" ]; then
        local PROXY_SERVER=$(scutil --proxy | awk '/HTTPProxy/ {print $3}')
        local PROXY_PORT=$(scutil --proxy | awk '/HTTPPort/ {print $3}')
        print_warn "系統代理設定" "已開啟 ($PROXY_SERVER:$PROXY_PORT)"
        add_error "偵測到本機 HTTP Proxy，若代理失效將導致無法上網。"
    fi
}

check_speedtest() {
    local GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
    if [ -n "$GATEWAY" ]; then
        local RTT=$(ping -c 3 -i 0.2 "$GATEWAY" 2>/dev/null | awk -F'/' '/avg/ {print $5}')
        [ -n "$RTT" ] && print_success "對內網路品質" "閘道 $GATEWAY 延遲: ${RTT} ms"
    fi

    if command -v networkQuality >/dev/null 2>&1; then
        local NQ_OUT=$(networkQuality -s 2>/dev/null)
        local DL=$(echo "$NQ_OUT" | awk '/Downlink capacity/ {printf "%.0f Mbps", $3}')
        local UL=$(echo "$NQ_OUT" | awk '/Uplink capacity/ {printf "%.0f Mbps", $3}')
        local RPM=$(echo "$NQ_OUT" | awk -F': ' '/Responsiveness/ {print $2}' | head -n 1)

        RPM=$(echo "$RPM" | sed -E \
            -e 's/High/優良 (極低延遲)/' \
            -e 's/Medium/普通 (一般順暢)/' \
            -e 's/Low/不佳 (滿載易卡頓)/' \
            -e 's/([0-9]+)(\.[0-9]+)? milliseconds/\1 毫秒/')

        if [ -n "$DL" ]; then
            if [ -n "$RPM" ]; then
                print_success "對外頻寬測試" "下行: $DL | 上行: $UL | 評級: $RPM"
            else
                print_success "對外頻寬測試" "下行: $DL | 上行: $UL"
            fi
            return
        fi
    fi

    local B_BYTES=$(curl -s -w "%{speed_download}" -o /dev/null "https://speed.cloudflare.com/__down?bytes=10000000" --max-time 5 2>/dev/null)
    if [ -n "$B_BYTES" ] && [ "$B_BYTES" != "0" ]; then
        local MBPS=$(awk -v b="$B_BYTES" 'BEGIN {printf "%.2f", (b * 8) / 1000000}')
        print_success "對外頻寬測試" "下行速度: $MBPS Mbps"
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
    local LOG_DIR="${NETOPSHUB_LOG_DIR:-$(dirname "$0")/logs}"
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
check_dependencies
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
