$StartSeconds = (Get-Date)
$OutputLog = ""
$JsonArray = @()

function append_log($text) {
    Write-Host $text
    $script:OutputLog += "$text`n"
}

function get_mac_vendor($mac) {
    if (!$mac -or $mac -eq "-") { return "" }
    $prefix = ($mac.Substring(0, 8) -replace '[:-]', '').ToUpper()
    switch -Regex ($prefix) {
        "^(B8F015|A0A001|001CB3|001E52|0023DF|002500|002608|040CCE|0C4DE9|1040F3|14109F|149877|18AF61|1CABA7|24AB81|28CFDA|341298|34C4F6|3C22FB|403CFC|409C28|444C0C|4C3275|508F4C|54E43A|58404E|5CF938|60FACD|64B9E8|64E682|6C4008|70A2B3|74E1B6|783A84|7CC537|804A14|843835|881FA1|8C8590|90FD61|94F6D6|98B000|98E0D9|A4B197|A8667F|AC3C0B|AC7BA1|B0481A|B4F61C|B817C2|BC52B7|C0847A|C42C03|C82A14|C8B5B7|CC08E0|D04DCB|D4619D|D81D72|DCA904|E0B9BA|E4CE8F|E88D28|F099B6|F40F24|F84E73|FCE998|0017F2|002312|086698|08F69C|10DDB1|28A8EA|34363B|4C7C5F|503275|50BC96|5C8D4E|5C95AE|600308|64A3CB|703EAC|784F43|787B8A|7CC3A1|80E650|844167|8CFABA|907240|941625|98FE94|A0999B|A88E24|A8BBCF|B88D12|B8C75D|C09AD0|C88550|CC29F5|CC4463|D4DCCD|E0C97A|E48B7F|EC852F|F0D1A9|F0DCE2|F4F951|F81EDF)" { return "Apple Device" }
        "^(001111|0017C4|001B21|001E67|00215C|002268|002314|0024D7|0026C7|3413E8|40E230|5891CF|606720|60F262|90E6BA|B499BA|C8F733|CC3D82|E006E6|ECF4BB|FCAA14|001500|00A0C9|00AA00)" { return "Intel Device" }
        "^(142D27|18D6C7|388C50|60A44C|68C44D|74DA38|A0F3C1|AC84C6|ACE010|C0A5DD|C0C9E3|D80D17|D84732|F81A67|F8D111|000AAB|001D0F|002127)" { return "TP-Link" }
        "^(04D4C4|086266|089E08|107B44|10BF48|14DDA9|18C04D|244BFE|2C4D54|2C56DC|305A3A|3497F6|382C4A|40167E|50465D|5404A6|54A050|6045CB|704D7B|74D02B|7824AF|88D7F6|9C5C8E|A85E45|AC220B|B06EBF|BCEE7B|C86000|D017C2|D850E6|E03F49|E4B97A|F02F74|F46AD1)" { return "ASUS" }
        "^(00E04C|0014D1|000B0E|00E04D|525400|5404A6)" { return "Realtek / QEMU" }
        "^(00155D|0003FF|00125A|281878|485073|501AC5|7C1E52|B48B19|C8348E)" { return "Microsoft" }
        "^(B827EB|DCA632)" { return "Raspberry Pi" }
        "^(001A11|001E10|0022B0|00248D|002637|0050F2|080028|100BA9|14CF92|18F46A|241FA0|30144A|342387|446D57|4844F7|50CCF8|549F13|5C0A5B|64B310|6CF373|784B87|8425DB|88329B|90187C|980C82|A021B7|A4E4B8|A80600|B0C090|B4CEF6|C4576E|C81479|CCF3A5|D022BE|D4E6B7|D890E8|E0AA96|E4B021|E8508B|EC1F72|F409D8|F832E4|FCF136)" { return "Samsung" }
        "^(000C29|005056|000569)" { return "VMware" }
        default { return "" }
    }
}

append_log "Intranet Recon & Port Scanner"
append_log "Host: $env:COMPUTERNAME | OS: Windows $((Get-CimInstance Win32_OperatingSystem).Caption)"
append_log "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
append_log "----------------------------------------"

$DefaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
if ($DefaultRoute) {
    $LocalIP = (Get-NetIPAddress -InterfaceIndex $DefaultRoute.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
}

if (!$LocalIP) {
    $LocalIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -notmatch "^127\." -and $_.IPAddress -notmatch "^169\.254" } | Select-Object -First 1).IPAddress
}

if (!$LocalIP) {
    append_log "[FATAL] 無法取得本機 IP，請確認網路連線。"
    exit 1
}

$LocalIP = [string]$LocalIP
$Subnet = $LocalIP -replace '\.\d+$',''
append_log " [INFO] 目標掃描網段: $Subnet.1 ~ 254"
append_log "----------------------------------------"

$Tasks = @()
1..254 | ForEach-Object {
    $IP = "$Subnet.$_"
    $Tasks += [System.Threading.Tasks.Task[string]]::Factory.StartNew([Func[object, string]] {
        param($targetIP)
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($targetIP, 1000)
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                return $targetIP
            }
        } catch {}
        return ""
    }, $IP)
}

try {
    [System.Threading.Tasks.Task]::WaitAll($Tasks) | Out-Null
} catch {}

$PingAlive = $Tasks | Where-Object { $_.Status -eq 'RanToCompletion' -and $_.Result -ne "" } | ForEach-Object { $_.Result }

$ArpTable = Get-NetNeighbor -AddressFamily IPv4 | Where-Object State -ne "Unreachable" | Select-Object IPAddress, LinkLayerAddress

$TotalFound = 0
$First = $true

1..254 | ForEach-Object {
    $IP = "$Subnet.$_"
    $Arp = $ArpTable | Where-Object IPAddress -eq $IP | Select-Object -First 1
    
    if (($PingAlive -contains $IP) -or $Arp -or ($IP -eq $LocalIP)) {
        $TotalFound++
        if (!$First) { append_log "  ------------------------------------------------------------" }
        $First = $false
        
        $OpenPorts = @()
        $PortsToCheck = @(22, 80, 443, 3389, 8000)
        foreach ($P in $PortsToCheck) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $async = $tcp.ConnectAsync($IP, $P)
                if ($async.Wait(150)) {
                    if ($tcp.Connected) { $OpenPorts += $P }
                }
                $tcp.Close()
            } catch {}
        }
        $PortStr = if ($OpenPorts.Count -gt 0) { $OpenPorts -join ", " } else { "無" }

        $DeviceType = "一般網路設備"
        if ($IP -eq $LocalIP) {
            $DeviceType = "Windows 主機 (本機控制臺)"
        } elseif ($OpenPorts -contains 22) {
            $DeviceType = "Linux / macOS 主機"
        } elseif ($OpenPorts -contains 3389) {
            $DeviceType = "Windows 主機"
        } elseif ($IP -eq "$Subnet.1") {
            $DeviceType = "路由器 / 閘道器"
        }

        $Mac = if ($Arp -and $Arp.LinkLayerAddress -and $Arp.LinkLayerAddress -notmatch "00-00-00-00") { $Arp.LinkLayerAddress -replace '-',':' } else { "-" }
        
        $Vendor = get_mac_vendor $Mac
        $MacPrint = if ($Vendor) { "$Mac ($Vendor)" } else { $Mac }
        
        append_log "[HOST] $IP │ $DeviceType"
        if ($Mac -ne "-") {
            append_log "        ├─ MAC: $MacPrint"
            append_log "        └─ Port: $PortStr"
        } else {
            append_log "        └─ Port: $PortStr"
        }

        $JsonObj = @{
            ip = $IP
            mac = $Mac
            device_type = $DeviceType
            vendor = $Vendor
            ports = $OpenPorts
        }
        $JsonArray += $JsonObj
    }
}

append_log "----------------------------------------"
if ($TotalFound -gt 0) {
    append_log "[探測結論] 內網主機探測完畢，共發現 $TotalFound 臺存活裝置。"
} else {
    append_log "[探測結論] 未發現任何存活主機，請確認網路連線與 Subnet 設定。"
}
append_log "----------------------------------------"

$Identifier = if ($env:CLIENT_IP) { $env:CLIENT_IP } else { "127.0.0.1" }

$LogDir = Join-Path $PSScriptRoot "logs"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

$JsonDir = Join-Path $PSScriptRoot "jsons"
if (!(Test-Path $JsonDir)) { New-Item -ItemType Directory -Path $JsonDir | Out-Null }

$Timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")

$LogFile = Join-Path $LogDir "Scan_${Identifier}_${Timestamp}.log"
$JsonFile = Join-Path $JsonDir "Scan_${Identifier}_${Timestamp}.json"

[System.IO.File]::WriteAllText($LogFile, $script:OutputLog, [System.Text.Encoding]::UTF8)

$JsonArray | ConvertTo-Json -Depth 3 | Out-File -FilePath $JsonFile -Encoding UTF8

$Duration = [math]::Round(((Get-Date) - $StartSeconds).TotalSeconds)
append_log " [INFO] 日誌已存至: logs/$(Split-Path $LogFile -Leaf)"
append_log " [INFO] 數據已存至: jsons/$(Split-Path $JsonFile -Leaf)"
append_log " [INFO] 總執行耗時: $Duration 秒"