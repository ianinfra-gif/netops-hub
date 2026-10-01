param (
    [string]$ServerIP = "127.0.0.1",
    [string]$ServerPort = "8000",
    [string]$ServerUrl = ""
)

$OutputLog = ""
$ErrorList = @()
$StartSeconds = (Get-Date)

function append_log($text) {
    Write-Host $text
    $script:OutputLog += "$text`n"
}

function print_success($label, $val) { append_log " [OK]   $label : $val" }
function print_error($label, $val)   { append_log " [FAIL] $label : $val" }
function print_warn($label, $val)    { append_log " [WARN] $label : $val" }
function print_info($label, $val)    { append_log " [INFO] $label : $val" }

function add_error($text) {
    $script:ErrorList += $text
    append_log "       -> 警示: $text"
}

function print_header() {
    append_log "Windows Network Diagnostic Tool"
    append_log "Host: $env:COMPUTERNAME | OS: $((Get-CimInstance Win32_OperatingSystem).Caption)"
    append_log "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    append_log "----------------------------------------"
}

function check_ipv4_status() {
    $DefaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
    $NetAdapter = $null
    
    if ($DefaultRoute) {
        $NetAdapter = Get-NetIPAddress -InterfaceIndex $DefaultRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (!$NetAdapter) {
        $NetAdapter = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -notmatch "^127\." -and $_.IPAddress -notmatch "^169\.254\." } | Select-Object -First 1
    }

    if ($null -ne $NetAdapter) {
        print_success "本機網卡狀態" "$($NetAdapter.InterfaceAlias) (IPv4: $($NetAdapter.IPAddress))"
    } else {
        print_error "本機網卡狀態" "未連線到任何網路介面"
        add_error "實體網路未連線，請確認實體線路或 Wi-Fi。"
    }
}

function check_wifi_radar() {
    $WlanInfo = netsh wlan show interfaces 2>$null
    if ($WlanInfo -match "SSID") {
        $SSID = ($WlanInfo | Select-String -Pattern "^\s*SSID\s*:\s*(.+)$").Matches.Groups[1].Value.Trim()
        $BSSID = ($WlanInfo | Select-String -Pattern "^\s*BSSID\s*:\s*(.+)$").Matches.Groups[1].Value.Trim()
        $Signal = ($WlanInfo | Select-String -Pattern "^\s*Signal\s*:\s*(.+)$").Matches.Groups[1].Value.Trim()
        $Rate = ($WlanInfo | Select-String -Pattern "^\s*Receive rate \(Mbps\)\s*:\s*(.+)$").Matches.Groups[1].Value.Trim()
        if ($SSID) {
            print_info "無線網路探測" "SSID: $SSID (BSSID: $BSSID)"
            print_info "無線網路品質" "強度: $Signal | 速率: ${Rate}Mbps"
        }
    }
}

function check_ipv6_conflict() {
    $IPv6Route = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix "::/0" -ErrorAction SilentlyContinue
    if ($IPv6Route) {
        $IPv6Test = Test-NetConnection -ComputerName "google.com" -IPv6 -WarningAction SilentlyContinue
        if ($IPv6Test.TcpTestSucceeded) {
            print_success "六號協定路由" "支援且連通"
        } else {
            print_warn "六號協定路由" "存在路由但無法連通 (封包遺失)"
            add_error "發現 IPv6 雙堆疊衝突，易導致連線逾時，建議暫時關閉 IPv6。"
        }
    }
}

function check_gateway() {
    $Gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    if ($Gateway) {
        if (Test-Connection -ComputerName $Gateway -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            print_success "預設閘道狀態" "$Gateway (連線正常)"
        } else {
            print_error "預設閘道狀態" "$Gateway (無法 Ping 通)"
            add_error "無法連線到本地路由器 ($Gateway)，請檢查內部網段狀態。"
        }
    } else {
        print_warn "預設閘道狀態" "無預設 Gateway"
    }
}

function check_arp_gateway() {
    $Gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    if ($Gateway) {
        $ArpEntry = Get-NetNeighbor -IPAddress $Gateway -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ArpEntry -and $ArpEntry.State -ne "Unreachable" -and $ArpEntry.LinkLayerAddress) {
            print_success "閘道位址解析" "Gateway MAC 正常 ($($ArpEntry.LinkLayerAddress -replace '-', ':'))"
        } else {
            print_warn "閘道位址解析" "無法解析閘道 $Gateway 的 MAC 位址"
            add_error "ARP 解析失敗，內網可能發生 IP 衝突或 ARP 欺騙。"
        }
    }
}

function check_vpn_and_mtu() {
    $VpnAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "VPN|TAP|TUN|PPP" -and $_.Status -eq "Up" } | Select-Object -First 1
    if ($VpnAdapter) {
        $VpnIP = (Get-NetIPAddress -InterfaceAlias $VpnAdapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
        print_success "虛擬通道狀態" "介面 $($VpnAdapter.Name) (IP: $($VpnIP))"
        $PingMtu = Test-Connection -ComputerName "1.1.1.1" -Count 1 -BufferSize 1200 -DontFragment -Quiet -ErrorAction SilentlyContinue
        if ($PingMtu) {
            print_success "傳輸單元狀態" "隧道寬度正常"
        } else {
            print_info "傳輸單元狀態" "隧道較窄 (系統已自動適應)"
        }
    } else {
        print_success "虛擬通道狀態" "介面 N/A (未開啟 VPN)"
        print_success "傳輸單元狀態" "傳輸正常"
    }
}

function check_wan_and_firewall() {
    if (Test-Connection -ComputerName "1.1.1.1" -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        print_success "網際網路直連" "1.1.1.1 (ICMP 通暢)"
        $Tcp80 = (Test-NetConnection -ComputerName "1.1.1.1" -Port 80 -WarningAction SilentlyContinue).TcpTestSucceeded
        $Tcp443 = (Test-NetConnection -ComputerName "1.1.1.1" -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
        if ($Tcp80 -and $Tcp443) {
            print_success "防火牆通訊埠" "Port 80/443 未被封鎖"
        } else {
            print_error "防火牆通訊埠" "TCP 連線被拒絕"
            add_error "ICMP 正常但 TCP 通訊埠被封鎖，請檢查防火牆或企業出口策略。"
        }
    } else {
        print_error "網際網路直連" "1.1.1.1 (斷線/封鎖)"
        $Trace = Test-NetConnection -ComputerName "1.1.1.1" -TraceRoute -Hops 4 -WarningAction SilentlyContinue
        $HopsStr = ($Trace.TraceRoute | Out-String).Trim()
        add_error "外網斷線。前 4 個路由節點狀態：`n$HopsStr"
    }
}

function check_captive_portal() {
    try {
        $WebTest = Invoke-WebRequest -Uri "http://www.msftconnecttest.com/connecttest.txt" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        if ($WebTest.Content -match "Microsoft Connect Test") {
            print_success "網路通行驗證" "無攔截 (未被驗證牆阻擋)"
        } else {
            print_warn "網路通行驗證" "偵測到 Captive Portal"
            add_error "連線被公共 Wi-Fi 登入頁面攔截，請完成網頁驗證。"
        }
    } catch {
        print_warn "網路通行驗證" "偵測到 Captive Portal"
        add_error "連線被公共 Wi-Fi 登入頁面攔截，請完成網頁驗證。"
    }
}

function check_dns_and_ssl() {
    $DnsServers = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Select-Object -First 1
    try {
        $DnsTest = Resolve-DnsName -Name "google.com" -QuickTimeout -ErrorAction Stop
        print_success "網域名稱解析" "google.com (解析正常)"
        try {
            $SslTest = Invoke-WebRequest -Uri "https://google.com" -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop
        } catch {
            print_warn "傳輸加密憑證" "驗證失敗 (時間錯誤)"
            add_error "HTTPS 憑證驗證失敗，請檢查系統時間是否準確。"
        }
    } catch {
        print_error "網域名稱解析" "失敗 (使用的 DNS: $($DnsServers))"
        add_error "網址無法解析。目前 DNS ($DnsServers) 無回應或遭污染。"
    }
}

function check_proxy() {
    $RegProxy = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($RegProxy.ProxyEnable -eq 1) {
        print_warn "系統代理設定" "已開啟 ($($RegProxy.ProxyServer))"
        add_error "偵測到本機 HTTP Proxy，若代理失效將導致無法上網。"
    }
}

function check_speedtest() {
    $Gateway = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    if ($Gateway) {
        $LanPing = Test-Connection -ComputerName $Gateway -Count 3 -ErrorAction SilentlyContinue | Measure-Object -Property ResponseTime -Average
        if ($LanPing.Average) {
            print_success "對內網路品質" "閘道 $Gateway 延遲: $([math]::Round($LanPing.Average, 1)) ms"
        }
    }

    try {
        $WebClient = New-Object System.Net.WebClient
        
        $Sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = $WebClient.DownloadData("https://speed.cloudflare.com/__down?bytes=10000000")
        $Sw.Stop()
        $SecDl = $Sw.Elapsed.TotalSeconds
        $DlMbps = "0.00"
        if ($SecDl -gt 0) { $DlMbps = [math]::Round(((10000000 * 8) / $SecDl) / 1000000, 2) }

        $Sw.Restart()
        $UpData = New-Object byte[] 5000000
        $null = $WebClient.UploadData("https://speed.cloudflare.com/__up", "POST", $UpData)
        $Sw.Stop()
        $SecUl = $Sw.Elapsed.TotalSeconds
        $UlMbps = "0.00"
        if ($SecUl -gt 0) { $UlMbps = [math]::Round(((5000000 * 8) / $SecUl) / 1000000, 2) }

        $WanPing = Test-Connection -ComputerName "1.1.1.1" -Count 3 -ErrorAction SilentlyContinue | Measure-Object -Property ResponseTime -Average
        $AvgMs = $WanPing.Average

        $Rating = "普通 (一般順暢)"
        if ($AvgMs -gt 0) {
            if ($AvgMs -lt 25) { $Rating = "優良 (極低延遲)" }
            elseif ($AvgMs -gt 80) { $Rating = "不佳 (滿載易卡頓)" }
        }

        if ($DlMbps -ne "0.00") {
            print_success "對外頻寬測試" "下行: $DlMbps Mbps | 上行: $UlMbps Mbps | 評級: $Rating"
        } else {
            print_warn "對外頻寬測試" "測速逾時或遭網路限制"
        }
    } catch {
        print_warn "對外頻寬測試" "測速逾時或遭網路限制"
    }
}

function print_summary() {
    append_log "----------------------------------------"
    if ($script:ErrorList.Count -eq 0) {
        append_log "[診斷結論] 網路狀態正常，未檢測到連線異常。"
    } else {
        append_log "[診斷結論] 發現連線異常，請參考以下警示項目："
        foreach ($err in $script:ErrorList) {
            append_log " $err"
        }
    }
    append_log "----------------------------------------"

    $Identifier = if ($env:CLIENT_IP) { $env:CLIENT_IP } else { "127.0.0.1" }
    $LogDir = Join-Path $PSScriptRoot "logs"
    if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogFile = Join-Path $LogDir "NetDiag_${Identifier}_${Timestamp}.log"

    $Duration = [math]::Round(((Get-Date) - $StartSeconds).TotalSeconds)
    append_log " [INFO] 檢測日誌已存至: logs/$(Split-Path $LogFile -Leaf)"
    append_log " [INFO] 總執行耗時: $Duration 秒"
    [System.IO.File]::WriteAllText($LogFile, $script:OutputLog, [System.Text.Encoding]::UTF8)

    if ($ServerUrl) {
        try {
            Invoke-WebRequest -Uri "$($ServerUrl.TrimEnd('/'))/upload_log" -Method Post -ContentType "text/plain; charset=utf-8" -InFile $LogFile -UseBasicParsing -TimeoutSec 10 | Out-Null
            Write-Host " [INFO] 檢測報告已回傳至控制臺"
        } catch {
            Write-Host " [WARN] 無法回傳報告，請確認控制臺網址與連線狀態"
        }
    }
}

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
