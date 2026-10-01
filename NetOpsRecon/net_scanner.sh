#!/bin/bash

TIMEOUT_PING=1
TIMEOUT_NC=1
SCAN_TMP_FILE="/tmp/net_scan_results_$$.tmp"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
DARK_GRAY='\033[38;5;238m'
NC='\033[0m'
BOLD='\033[1m'

LOG_TEXT=""
START_SECONDS=$(date +%s)
TOTAL_FOUND=0

append_log() { LOG_TEXT+="$1\n"; }

print_header() {
    local HOST_NAME=$(hostname -s)
    local OS_VER="Linux"
    if command -v sw_vers >/dev/null 2>&1; then
        OS_VER="macOS $(sw_vers -productVersion)"
    elif [ -f /etc/os-release ]; then
        OS_VER=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    fi
    
    echo -e "${BOLD}Intranet Recon & Port Scanner${NC}"
    echo -e "Host: $HOST_NAME | OS: $OS_VER"
    echo -e "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "----------------------------------------"
    
    append_log "Intranet Recon & Port Scanner"
    append_log "Host: $HOST_NAME | OS: $OS_VER"
    append_log "Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
    append_log "----------------------------------------"
}

normalize_mac() {
    local RAW_MAC="$1"
    [ -z "$RAW_MAC" ] && return
    echo "$RAW_MAC" | awk -F: '{for(i=1;i<=NF;i++) if(length($i)==1) $i="0"$i; print $1":"$2":"$3":"$4":"$5":"$6}' | tr 'A-Z' 'a-z'
}

get_vendor() {
    local RAW_MAC="$1"
    [ -z "$RAW_MAC" ] && return
    local MAC=$(echo "$RAW_MAC" | tr 'a-z' 'A-Z')

    if [[ "${MAC:1:1}" =~ [26AE] ]]; then
        echo "Randomized MAC"
        return
    fi

    case "${MAC:0:8}" in
        B8:F0:15|A8:BA:25|A0:A0:01|28:70:FD|DC:A9:04|F0:18:98|00:16:CB|4C:32:75|AC:BC:32|BC:D2:48|F8:FF:C2|18:65:90|3C:06:30|04:0C:CE|14:98:77|20:C9:D0|34:36:3B|38:CA:54|40:33:1A|48:D7:C5|50:BC:E6|54:E4:3A|5C:E9:1E|60:F8:1D|64:B9:E8|68:FE:F7|70:56:81|78:4F:43|7C:D1:C3|80:E6:50|84:38:35|88:66:A5|8C:85:90|90:9C:4A|98:01:A7|A4:5E:60|AC:DE:48|B0:CA:70|BC:A9:20|C0:CC:07|C8:BC:C8|D0:81:7A|D8:A2:5E|E0:AC:CB|E8:80:2E|F4:0F:24|FC:FC:2A|5C:9B:A6|00:17:F2|00:1C:B3|00:1E:C2|00:1F:5B|00:1F:F3|00:21:E9|00:22:12|00:23:12|00:23:3D|00:23:6C|00:24:36|00:25:00|00:25:4B|00:26:08|00:26:4A|00:26:BB|80:A9:97)
            echo "Apple Device" ;;
        A0:25:D7|00:08:C7|00:0B:CD|00:0E:7F|00:11:0A|00:12:79|00:13:21|00:14:C2|00:15:60|00:16:35|00:17:A4|00:18:71|00:19:BB|00:1A:4B|00:1B:78|00:1C:23|00:1D:09|00:1E:0B|00:1F:29|00:21:5A|00:22:64|00:23:7D|00:24:81|00:25:B3|00:26:55|10:1F:74|14:58:D0|1C:C1:DE|28:80:23|3C:D9:2B|64:51:06|98:4B:4A|A0:B3:CC|B4:B5:2F|C8:C1:26|D4:85:64|E8:2A:44|EC:8B:A8|F4:CE:46)
            echo "HP" ;;
        00:06:5B|00:08:74|00:0B:DB|00:0D:56|00:0F:1F|00:11:43|00:12:3F|00:13:72|00:14:22|00:15:C5|00:16:F0|00:18:8B|00:19:B9|00:1A:A0|00:1C:23|00:1D:09|00:1E:4F|00:21:70|00:22:19|00:23:AE|00:24:E8|00:25:64|00:26:B9|18:03:73|14:FE:B5|34:17:EB|44:A8:42|74:86:7A|84:2B:2B|A4:1F:72|B8:CA:3A|D4:AE:52|E0:DB:55|F8:BC:12)
            echo "Dell" ;;
        00:10:A7|00:16:17|00:19:DB|00:1D:92|00:21:85|00:24:21|00:26:18|0C:9D:92|14:DA:E9|18:C0:4D|2C:F0:5D|30:9C:23|40:8D:5C|44:8A:5B|7C:10:C9|8C:89:A5|A4:BF:01|D4:3D:7E|DB:B1:33|E0:CB:4E)
            echo "MSI" ;;
        00:02:B3|00:03:47|00:04:23|00:0E:0C|00:13:20|00:13:E8|00:15:00|00:16:EA|00:18:DE|00:19:D2|00:1B:21|00:1C:C0|00:1D:E0|00:1E:64|00:1F:3C|00:21:6A|00:22:FB|00:23:14|00:24:D7|00:26:C7|00:27:0E|00:1A:A0|3C:F8:62|48:51:B7|5C:51:88|60:57:18|64:00:6A|68:05:CA|70:85:C2|78:2B:46|80:86:F2|84:A6:C8|8C:70:5A|90:E2:BA|98:4F:EE|A0:36:BC|A4:4C:C8|B4:2E:99|C8:5B:76|D0:C5:D3|E0:D5:5E|E4:A4:71|F8:63:3F)
            echo "Intel" ;;
        00:12:FE|00:1A:6B|00:21:A0|00:59:07|10:7B:44|14:9F:E8|20:1A:06|28:39:26|3C:97:0E|40:16:3B|50:7B:9D|60:99:D1|70:72:3C|80:3F:5D|88:70:8C|A4:8C:DB|B8:88:E3|D4:25:8B|E8:6A:64)
            echo "Lenovo" ;;
        00:0C:6E|00:0E:A6|00:11:2F|00:13:D4|00:15:F2|00:17:31|00:1B:FC|00:1E:8C|00:22:15|00:23:54|00:25:22|00:1D:7E|04:D9:F5|18:31:BF|2C:4D:54|38:2C:4A|50:46:5D|70:8B:CD|AC:22:0B|D0:17:C2|E0:3F:49|F8:32:E4)
            echo "ASUS" ;;
        00:07:08|00:0A:CD|00:14:D1|00:20:18|00:E0:4C|18:66:DA|20:CF:30|52:54:4C|B8:2A:72)
            echo "Realtek" ;;
        00:80:24|00:E0:98|00:00:0C|00:01:42|00:02:FC|00:03:E3|00:04:4D|00:05:32|00:06:52|00:07:0E|00:08:20|00:09:11|00:0A:41|00:0B:45|00:0C:CE|00:0D:28|00:0E:38|00:0F:23|00:10:11|00:11:20|00:12:00|00:13:19|00:14:69|00:15:2B|00:16:46|00:17:0E|00:18:18|00:19:07|00:1A:2B|00:1B:0C|00:1C:0E|00:1D:45|00:1E:13|00:1F:27|00:21:1B|00:22:55|00:23:04|00:24:14|00:25:45|00:26:0B)
            echo "Cisco" ;;
        00:11:32|00:11:24|90:09:D0|00:08:9B)
            echo "Synology NAS" ;;
        00:0A:EB|00:14:D1|00:1D:AA|00:27:19|08:60:6E|10:FE:ED|14:CC:20|18:A6:F7|28:2C:B2|30:B5:C2|50:C7:BF|60:E3:27|70:4F:57|84:16:F9|94:D7:0E|A0:F3:C1|B0:48:7A|C0:25:E9|D8:07:B6|E8:94:F6|F4:EC:38)
            echo "TP-Link" ;;
        00:1F:33|00:26:5A|08:11:96|10:0C:6B|14:59:C0|1C:1B:68|20:4E:71|28:80:88|30:23:03|38:94:96|40:5D:82|48:8D:36|50:65:F3|64:66:B3|6C:B0:CE|74:88:8B|78:D6:F0|84:A9:38|8C:3B:AD|94:A7:B7|9C:3D:CF|A0:63:91|A4:2B:B0|B0:39:56|B4:75:0E|BC:A5:11|C0:FF:D4|C8:D7:19|D4:6A:91|E0:46:9A|E4:F4:C6|EC:17:2F|F4:6D:E2|FC:A1:83)
            echo "Netgear" ;;
        00:00:F0|00:02:78|00:07:AB|00:09:18|00:0D:AE|00:12:FB|00:13:77|00:15:99|00:16:6C|00:17:C9|00:18:AF|00:1A:8A|00:1C:43|00:1D:25|00:1E:7D|00:1F:CC|00:21:19|00:23:39|00:24:54|00:25:66|00:26:5D|08:37:3D|14:BB:6E|18:3A:2D|1C:5A:3E|2C:44:01|38:0B:40|40:0E:85|4C:BC:A5|50:01:D9|54:88:0E|5C:0A:5B|64:7B:CE|70:2C:1F|78:4B:87|84:25:DB|88:32:9B|94:01:C2|98:52:B1|A0:82:1F|AC:5F:3E|B0:EC:71|C0:BD:D1|CC:3A:61|D0:22:BE|D8:57:EF|E0:99:71|F0:25:B7|F4:7B:5E)
            echo "Samsung" ;;
        00:9E:C8|04:CF:8C|0C:98:38|14:F6:5A|18:59:36|28:6C:07|34:80:B3|3C:BD:3E|58:41:88|64:09:80|68:DF:DD|74:23:44|7C:1D:D9|8C:BE:BE|98:FA:E3|A4:45:19|C8:D3:FF|D4:61:9D|F4:8E:92)
            echo "Xiaomi" ;;
        00:05:85|00:09:A4|00:0B:09|00:0E:5E|00:12:72|00:14:6C|00:18:82|00:19:A5|00:1E:10|00:22:A1|00:25:9E|00:2E:C7|04:25:C5|08:19:A6|0C:37:DC|10:1B:54|14:30:04|18:C5:8A|1C:1D:67|20:08:89|24:09:95|28:6E:D4|2C:CF:58|30:87:30|34:00:A3|38:BC:01|3C:F5:CC|40:CB:A8|44:82:E5|48:46:FB|4C:1F:CC|50:9F:A3|54:89:98|58:60:5F|5C:B4:3E|60:DE:44|64:16:8D|68:A0:36|6C:11:79|70:72:0D|74:88:2A|78:6A:89|7C:60:97|80:38:BC|84:DB:AC|88:CE:FA|8C:34:FD|90:17:AC|94:71:AC|98:1A:18|9C:37:F4|A0:8C:FD|A4:99:47|A8:CA:7B|AC:E2:15|B0:08:75|B4:15:13|B8:94:70|BC:76:70|C0:70:09|C4:07:2F|C8:D1:5E|CC:96:A0|D0:2D:B3|D4:6A:A8|D8:49:0B|DC:D2:FC|E0:24:7F|E4:C2:D1|E8:08:8B|EC:23:3D|F0:98:38|F4:55:9C|F8:E8:11|FC:48:EF)
            echo "Huawei" ;;
        00:05:69|00:0C:29|00:1C:14|00:50:56)
            echo "VMware Virtual Machine" ;;
        08:00:27)
            echo "VirtualBox VM" ;;
        52:54:00)
            echo "QEMU/KVM VM" ;;
        00:01:4A|00:02:A5|00:04:1F|00:0A:D9|00:0B:E1|00:0E:07|00:13:15|00:15:C1|00:19:C5|00:1B:66|00:1D:0D|00:1E:45|00:1F:A7|00:24:8D|00:26:43|00:2B:B0|04:76:6E|08:00:46|28:0D:FC|70:9E:29|78:C8:81|A8:E3:EE|C4:9D:ED|F8:D0:AC)
            echo "Sony PlayStation" ;;
        00:09:BF|00:17:AB|00:19:FD|00:1B:7A|00:1E:A9|00:21:47|00:22:AA|00:23:CC|00:24:11|00:25:A0|00:26:59|04:03:D6|18:2A:7B|20:0C:C8|2C:10:C1|34:AF:2C|40:F4:07|78:A2:A0|8C:56:C5|98:41:5C|A4:5C:27|B8:AE:6E|C8:F9:EE|CC:9E:00|D8:6B:F7|E0:0C:7F|E4:0C:7F|F8:27:C5)
            echo "Nintendo Console" ;;
        00:0D:3A|00:12:5A|00:15:5D|00:17:FA|00:1D:D8|00:22:48|00:25:AE|00:50:F2|28:18:78|30:59:B7|48:50:73|50:1A:C5|5C:BA:37|60:45:BD|7C:ED:8D|90:B0:ED|A0:CE:C8|C8:3F:26|DC:B4:C4|E4:A7:A5|F4:60:E2)
            echo "Microsoft Xbox / Host" ;;
        *)
            echo "Other Device" ;;
    esac
}

get_hostname() {
    local IP="$1"
    local HOST=""
    if command -v dig >/dev/null 2>&1; then
        HOST=$(dig -x "$IP" +short +time=1 +tries=1 2>/dev/null | sed 's/\.$//' | head -n 1)
    fi
    if [ -z "$HOST" ] && command -v nslookup >/dev/null 2>&1; then
        HOST=$(nslookup -timeout=1 "$IP" 2>/dev/null | awk -F'= ' '/name =/ {print $2}' | sed 's/\.$//' | head -n 1)
    fi
    [[ "$HOST" == "N/A" || "$HOST" == *"in-addr.arpa"* ]] && HOST=""
    echo "$HOST"
}

get_http_banner() {
    local IP="$1"
    local PORTS="$2"
    local BANNER=""

    if [[ "$PORTS" == *80* || "$PORTS" == *443* || "$PORTS" == *631* || "$PORTS" == *8000* || "$PORTS" == *8080* ]]; then
        BANNER=$(curl -sI --max-time 1 "http://$IP" 2>/dev/null | grep -i "^Server:" | awk -F': ' '{print $2}' | tr -d '\r\n')
        [ -z "$BANNER" ] && BANNER=$(curl -skI --max-time 1 "https://$IP" 2>/dev/null | grep -i "^Server:" | awk -F': ' '{print $2}' | tr -d '\r\n')
    fi
    echo "$BANNER"
}

infer_device_type() {
    local VENDOR="$1"
    local TTL="$2"
    local PORTS="$3"
    local HOST="$4"
    local LAST_OCTET="$5"
    local BANNER="$6"
    local TARGET_IP="$7"
    local LOCAL_IP="$8"

    local LOWER_HOST=$(echo "$HOST" | tr 'A-Z' 'a-z')
    local LOWER_BANNER=$(echo "$BANNER" | tr 'A-Z' 'a-z')

    if [[ -n "$LOCAL_IP" && "$TARGET_IP" == "$LOCAL_IP" ]]; then
        echo "Linux 電腦 (本機控制臺)"
        return
    fi

    if [[ "$VENDOR" == "Apple Device" ]] || [[ "$LOWER_HOST" =~ (macbook|imac|macmini|macpro|apple) ]]; then
        if [[ "$LOWER_HOST" =~ (iphone|ipad) ]]; then
            echo "Apple 手機/平板 ($HOST)"
            return
        elif [[ "$PORTS" == *22* || "$PORTS" == *5900* || "$PORTS" == *8000* || "$PORTS" == *631* || "$LOWER_HOST" =~ (macbook|imac|macmini|macpro) ]]; then
            if [[ "$PORTS" == *7000* ]]; then
                echo "Mac 電腦 (AirPlay 接收卡)"
            else
                echo "Mac 電腦"
            fi
            return
        elif [[ "$PORTS" == *7000* || "$PORTS" == *62078* ]]; then
            echo "Apple 手機/平板 (AirPlay)"
            return
        else
            echo "Apple 裝置"
            return
        fi
    fi

    if [[ "$PORTS" == *9100* ]] || [[ "$LOWER_HOST" =~ (printer|epson|canon|hp|brother|ricoh|kyocera|fuji|xerox) ]] || [[ "$LOWER_BANNER" =~ (epson|canon|hp|brother|papercut|cups|jetdirect) ]]; then
        if [ -n "$BANNER" ]; then
            echo "印表機 ($BANNER)"
        else
            echo "印表機"
        fi
        return
    fi

    if [[ "$PORTS" == *631* ]]; then
        echo "印表機"
        return
    fi

    if [[ "$PORTS" == *7000* || "$PORTS" == *62078* ]]; then
        echo "Apple 手機/平板 (AirPlay)"
        return
    fi

    if [[ "$PORTS" == *8008* || "$PORTS" == *8009* ]]; then
        echo "Android 手機/平板 (Cast)"
        return
    fi

    if [[ "$PORTS" == *5000* || "$PORTS" == *5001* || "$PORTS" == *548* ]] || [[ "$LOWER_HOST" =~ (synology|qnap|nas) ]] || [[ "$VENDOR" == "Synology NAS" ]]; then
        echo "NAS 儲存設備"
        return
    fi

    if [[ "$PORTS" == *3389* || "$PORTS" == *445* ]]; then
        echo "Windows 電腦"
        return
    fi

    if [[ "$LAST_OCTET" == "1" || "$LAST_OCTET" == "254" ]] || [[ "$VENDOR" =~ (Cisco|ASUS|TP-Link|Netgear|D-Link|MikroTik) ]]; then
        if [ -n "$BANNER" ]; then
            echo "路由器/AP ($BANNER)"
        else
            echo "路由器 / AP"
        fi
        return
    fi

    if [[ "$LOWER_HOST" =~ (iphone|ipad) ]]; then
        echo "Apple 手機/平板 ($HOST)"
        return
    fi

    if [[ "$LOWER_HOST" =~ (android|galaxy|pixel|xiaomi|samsung|huawei) ]]; then
        echo "Android 手機/平板 ($HOST)"
        return
    fi

    if [[ "$VENDOR" == "Randomized MAC" ]]; then
        if (( TTL == 128 )); then
            echo "Windows 筆電 (Wi-Fi)"
        else
            echo "手機 / 平板 (Wi-Fi 隨機 MAC)"
        fi
        return
    fi

    if [[ "$VENDOR" =~ (Realtek|Intel|MSI|HP|Dell|Lenovo|Acer|Gigabyte|ASUS) ]]; then
        echo "$VENDOR 主機"
        return
    fi

    if (( TTL == 128 )); then
        echo "Windows 主機"
        return
    fi

    echo "一般網路設備"
}

scan_subnet() {
    local LOCAL_IP=""
    
    if [ "$(uname)" = "Darwin" ]; then
        local DEF_DEV=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
        [ -n "$DEF_DEV" ] && LOCAL_IP=$(ifconfig "$DEF_DEV" 2>/dev/null | awk '/inet / {print $2}')
    else
        LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        [ -z "$LOCAL_IP" ] && LOCAL_IP=$(ip -4 addr show 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v '127.0.0.1' | head -n 1)
    fi

    if [ -z "$LOCAL_IP" ]; then
        echo -e "${RED}[FATAL] 無法取得本機 IP，請確認網路連線。${NC}"
        exit 1
    fi
    
    local SUBNET=$(echo "$LOCAL_IP" | awk -F. '{print $1"."$2"."$3}')
    echo -e " [${CYAN}INFO${NC}] 目標掃描網段: ${BOLD}${SUBNET}.1 ~ 254${NC}"
    append_log " [INFO] 目標掃描網段: $SUBNET.1 ~ 254"
    echo -e "----------------------------------------"
    append_log "----------------------------------------"
    
    local PORTS=(22 80 443 445 5000 5900 631 3389 7000 8008 8000 8080 9100)
    > "$SCAN_TMP_FILE"
    
    for i in {1..254}; do
        local TARGET_IP="$SUBNET.$i"
        (
            local PING_OUT=""
            local PING_RES=1
            
            if [ "$(uname)" = "Darwin" ]; then
                PING_OUT=$(ping -n -c 1 -t 1 "$TARGET_IP" 2>/dev/null)
                PING_RES=$?
            else
                PING_OUT=$(ping -n -c 1 -W 1 "$TARGET_IP" 2>/dev/null)
                PING_RES=$?
            fi
            
            local MAC_RAW=$(arp -n "$TARGET_IP" 2>/dev/null | grep -oE '([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}' | head -n 1)
            [ -z "$MAC_RAW" ] && MAC_RAW=$(ip neighbor show "$TARGET_IP" 2>/dev/null | grep -oE '([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}' | head -n 1)

            if [[ $PING_RES -eq 0 || -n "$MAC_RAW" ]]; then
                local HOSTNAME=$(get_hostname "$TARGET_IP")
                local TTL=0
                [ $PING_RES -eq 0 ] && TTL=$(echo "$PING_OUT" | awk -F'ttl=' '{print $2}' | awk '{print $1}' | tr -d 'ms' | tr -d '\n')
                [[ -z "$TTL" ]] && TTL=0

                local OPEN_PORTS=()
                for p in "${PORTS[@]}"; do
                    if [ "$(uname)" = "Darwin" ]; then
                        nc -n -G 1 -z "$TARGET_IP" "$p" >/dev/null 2>&1 && OPEN_PORTS+=("$p")
                    else
                        nc -n -w 1 -z "$TARGET_IP" "$p" >/dev/null 2>&1 && OPEN_PORTS+=("$p")
                    fi
                done
                local PORT_STR=$(IFS=,; echo "${OPEN_PORTS[*]}")
                local MAC_PAD=""
                [ -n "$MAC_RAW" ] && MAC_PAD=$(normalize_mac "$MAC_RAW")
                local VENDOR=""
                [ -n "$MAC_PAD" ] && VENDOR=$(get_vendor "$MAC_PAD")
                local BANNER=$(get_http_banner "$TARGET_IP" "$PORT_STR")
                local DEV_TYPE=$(infer_device_type "$VENDOR" "$TTL" "$PORT_STR" "$HOSTNAME" "$i" "$BANNER" "$TARGET_IP" "$LOCAL_IP")

                echo "${TARGET_IP}|${MAC_PAD:-NONE}|${VENDOR:-NONE}|${HOSTNAME:-NONE}|${PORT_STR:-NONE}|${DEV_TYPE:-一般網路設備}|${TTL}" >> "$SCAN_TMP_FILE"
            fi
        ) &
        
        if (( i % 127 == 0 )); then
            wait
        fi
    done
    wait
    
    if [ -s "$SCAN_TMP_FILE" ]; then
        sort -t . -k 4,4n "$SCAN_TMP_FILE" > "${SCAN_TMP_FILE}.sorted"
        local IS_FIRST=1
        while IFS='|' read -r IP MAC VENDOR HOST PORT_STR DEV_TYPE TTL; do
            [[ "$MAC" == "NONE" ]] && MAC=""
            [[ "$VENDOR" == "NONE" ]] && VENDOR=""
            [[ "$HOST" == "NONE" ]] && HOST=""
            [[ "$PORT_STR" == "NONE" ]] && PORT_STR=""
            [ -z "$MAC" ] && [ -z "$PORT_STR" ] && [ -z "$HOST" ] && continue

            ((TOTAL_FOUND++))

            if [ $IS_FIRST -eq 0 ]; then
                echo -e "  ${DARK_GRAY}────────────────────────────────────────────────────────────${NC}"
                append_log "  ------------------------------------------------------------"
            fi
            IS_FIRST=0

            printf -v IP_PAD "%-15s" "$IP"
            echo -e " [${GREEN}HOST${NC}] ${BOLD}${IP_PAD}${NC}  │  ${PURPLE}${DEV_TYPE}${NC}"
            append_log "[HOST] $IP │ $DEV_TYPE"
            
            local DETAILS=()
            [[ -n "$HOST" ]] && DETAILS+=("Host: $HOST")
            [[ -n "$MAC" ]] && DETAILS+=("MAC: $MAC (${CYAN}${VENDOR}${NC})")
            
            if [[ -n "$PORT_STR" ]]; then
                local PORTS_FORMATTED=$(echo "$PORT_STR" | tr ',' ' ' | sed 's/  */, /g')
                DETAILS+=("Port: ${GREEN}${PORTS_FORMATTED}${NC}")
            fi

            if [ ${#DETAILS[@]} -eq 0 ]; then
                DETAILS+=("Status: 存活主機 (ICMP 響應)")
            fi

            local TOTAL_ITEMS=${#DETAILS[@]}
            for ((idx=0; idx<TOTAL_ITEMS; idx++)); do
                local CONNECTOR="├─"
                [ $idx -eq $((TOTAL_ITEMS - 1)) ] && CONNECTOR="└─"
                echo -e "        ${CONNECTOR} ${DETAILS[$idx]}"
                local CLEAN_LINE=$(echo "${DETAILS[$idx]}" | sed 's/\x1b\[[0-9;]*m//g')
                append_log "       ${CONNECTOR} ${CLEAN_LINE}"
            done
        done < "${SCAN_TMP_FILE}.sorted"
        rm -f "${SCAN_TMP_FILE}.sorted"
    fi
}

generate_json() {
    local JSON_FILE="$1"
    echo "{" > "$JSON_FILE"
    echo "  \"timestamp\": \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\"," >> "$JSON_FILE"
    echo "  \"results\": [" >> "$JSON_FILE"
    if [ -f "$SCAN_TMP_FILE" ]; then
        local TOTAL_LINES=$(wc -l < "$SCAN_TMP_FILE" | awk '{print $1}')
        local CURRENT_LINE=0
        while IFS='|' read -r IP MAC VENDOR HOST PORT_STR DEV_TYPE TTL; do
            [[ "$MAC" == "NONE" ]] && MAC=""
            [[ "$VENDOR" == "NONE" ]] && VENDOR=""
            [[ "$HOST" == "NONE" ]] && HOST=""
            [[ "$PORT_STR" == "NONE" ]] && PORT_STR=""
            [ -z "$MAC" ] && [ -z "$PORT_STR" ] && [ -z "$HOST" ] && continue

            ((CURRENT_LINE++))
            echo "    {" >> "$JSON_FILE"
            echo "      \"ip\": \"$IP\"," >> "$JSON_FILE"
            echo "      \"device_type\": \"$DEV_TYPE\"," >> "$JSON_FILE"
            echo "      \"ttl\": $TTL," >> "$JSON_FILE"
            echo "      \"mac\": \"$MAC\"," >> "$JSON_FILE"
            echo "      \"vendor\": \"$VENDOR\"," >> "$JSON_FILE"
            echo "      \"hostname\": \"$HOST\"," >> "$JSON_FILE"
            if [ -z "$PORT_STR" ]; then
                echo "      \"open_ports\": []" >> "$JSON_FILE"
            else
                local JSON_PORTS=$(echo "$PORT_STR" | awk -F, '{for(i=1;i<=NF;i++) printf "\"%s\"%s", $i, (i==NF?"":",")}')
                echo "      \"open_ports\": [$JSON_PORTS]" >> "$JSON_FILE"
            fi
            echo "    }$( [ "$CURRENT_LINE" -eq "$TOTAL_LINES" ] || echo "," )" >> "$JSON_FILE"
        done < "$SCAN_TMP_FILE"
        rm -f "$SCAN_TMP_FILE"
    fi
    echo "  ]" >> "$JSON_FILE"
    echo "}" >> "$JSON_FILE"
}

print_summary() {
    echo -e "----------------------------------------"
    append_log "----------------------------------------"
    if (( TOTAL_FOUND > 0 )); then
        echo -e "${PURPLE}${BOLD}[探測結論] 內網主機探測完畢，共發現 ${TOTAL_FOUND} 臺存活裝置。${NC}"
        append_log "[探測結論] 內網主機探測完畢，共發現 ${TOTAL_FOUND} 臺存活裝置。"
    else
        echo -e "${YELLOW}${BOLD}[探測結論] 未發現任何存活主機，請確認網路連線與 Subnet 設定。${NC}"
        append_log "[探測結論] 未發現任何存活主機，請確認網路連線與 Subnet 設定。"
    fi
    echo -e "----------------------------------------"
    append_log "----------------------------------------"
    
    local IDENTIFIER="${CLIENT_IP:-127.0.0.1}"
    local LOG_DIR="$(dirname "$0")/logs"
    local JSON_DIR="$(dirname "$0")/jsons"
    mkdir -p "$LOG_DIR" "$JSON_DIR"
    
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local LOG_FILE="$LOG_DIR/Scan_${IDENTIFIER}_${TIMESTAMP}.log"
    local JSON_FILE="$JSON_DIR/Scan_${IDENTIFIER}_${TIMESTAMP}.json"
    
    echo -e "$LOG_TEXT" | sed 's/\x1b\[[0-9;]*m//g' > "$LOG_FILE"
    generate_json "$JSON_FILE"
    
    local DURATION=$(($(date +%s) - START_SECONDS))
    echo -e " [INFO] 日誌已存至: logs/$(basename "$LOG_FILE")"
    echo -e " [INFO] 數據已存至: jsons/$(basename "$JSON_FILE")"
    echo -e " [INFO] 總執行耗時: ${DURATION} 秒"
}

print_header
scan_subnet
print_summary