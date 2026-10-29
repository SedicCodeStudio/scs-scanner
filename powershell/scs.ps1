<#
.SYNOPSIS
    SCS Scanner (PowerShell edition) - checks this computer for spyware, malware, hidden files and
    redirected traffic. Needs no Python and no other downloads.

.DESCRIPTION
    Native PowerShell version of the SCS Scanner by Sedic Code Studio (Apache License 2.0).
    Read-only by default: nothing on the computer is changed unless you use -Quarantine or -Restore.
    Runs on Windows PowerShell 5.1 and PowerShell 7. On macOS/Linux (pwsh) only the cross-platform
    checks run; use the Python version there for the full scan.

    Indicators of compromise are downloaded straight from their public sources (mvt-project/mvt-indicators:
    Pegasus, Predator, RCS Lab, QuaDream, Candiru, stalkerware and more; Zero Breach: AdFection).
    The format of indicators, quarantine, baseline and JSON reports is shared with the Python version.

.PARAMETER Mode
    Quick (default) or Full. Full adds signature checks, hidden data streams and data appended to images.
.PARAMETER Update
    Download the indicator lists now (otherwise they are updated automatically when older than 7 days).
.PARAMETER NoUpdate
    Never download anything (offline scan with the lists already present).
.PARAMETER Report
    Path of the HTML report. Default: ~/.scs-scanner/reports/SCS-Report-<date>.html
.PARAMETER Json
    Additionally save a JSON report (can be combined with other devices: "scs merge" in the Python version).
.PARAMETER Open
    Open the HTML report in the browser when the scan is done.
.PARAMETER SelfTest
    Harmless test: creates a test file, detects it and moves it to quarantine.
.PARAMETER Quarantine
    Move the given file to quarantine (it is never deleted).
.PARAMETER Restore
    Restore the quarantine entry with this ID.
.PARAMETER DeleteQuarantine
    Permanently delete the quarantine entry with this ID.
.PARAMETER ListQuarantine
    Show the quarantine.
.PARAMETER NoBaseline
    Do not compare with the last scan (change detection).
.PARAMETER NoColor
    Plain output without colours.
.PARAMETER Version
    Show the version and exit.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scs.ps1 -Open
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scs.ps1 -Mode Full -Json "$env:USERPROFILE\Desktop\scan.json"
#>
[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Full')][string]$Mode = 'Quick',
    [switch]$Update,
    [switch]$NoUpdate,
    [string]$Report,
    [string]$Json,
    [switch]$Open,
    [switch]$SelfTest,
    [string]$Quarantine,
    [string]$Restore,
    [string]$DeleteQuarantine,
    [switch]$ListQuarantine,
    [switch]$NoBaseline,
    [switch]$NoColor,
    [switch]$Version
)

Set-StrictMode -Version 1.0
# started as a .ps1 file (then "exit" sets the exit code) or as a script block from a one-line command
$Script:RunAsFile = -not [string]::IsNullOrEmpty($MyInvocation.MyCommand.Path)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ------------------------------------------------------------------ settings
$Script:AppVersion = '0.2.0'
$Script:IsWin = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$Script:UserHome = $HOME
if ($env:SCS_HOME) { $Script:UserHome = $env:SCS_HOME }   # used by the test suite
$Script:DataDir = Join-Path $Script:UserHome '.scs-scanner'
$Script:IocDir = Join-Path $Script:DataDir 'indicators'
$Script:TmpDir = Join-Path $Script:DataDir 'tmp'
$Script:QDir = Join-Path $Script:DataDir 'quarantine'
$Script:BaseDir = Join-Path $Script:DataDir 'baseline'
$Script:ReportDir = Join-Path $Script:DataDir 'reports'
$Script:IndexUrl = 'https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml'
$Script:ExtraFeeds = @(@{ name = 'Zero Breach - AdFection / Candiru (2026)'; url = 'https://github.com/interplains/zero-breach/releases/latest/download/adfection.stix.json' })
$Script:SelfTestText = "SCS-SELFTEST: harmless test file of the SCS Scanner. Safe to delete.`n"
$Script:Findings = New-Object System.Collections.Generic.List[object]
$Script:Snap = @{}
$Script:Procs = @()
$Script:Vpn = @()
$Script:IOC = @{ domain = @{}; ipv4 = @{}; sha256 = @{}; process = @{}; file_path = @{}; app_id = @{}; email = @{} }
$Script:Feeds = New-Object System.Collections.Generic.List[object]
$Script:Started = Get-Date

$SuspDirs = '\\(appdata|temp|tmp|users\\public|programdata|downloads|\$recycle\.bin)\\'
$SuspCmd = '(-enc(odedcommand)?\s|frombase64string|downloadstring|invoke-expression|\biex\b|mshta(\.exe)?\s+(http|javascript|vbscript)|rundll32(\.exe)?\s+javascript|regsvr32.*/i:http|bitsadmin.*/transfer|certutil.*-urlcache|wscript.*\\appdata|cscript.*\\appdata|powershell.*-w(indowstyle)?\s+hidden)'
$MsOk = '\\(microsoft|windows defender|windowsapps|onedrive|google\\update|mozilla maintenance)\\'
$ExecExt = @('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.jar', '.msi', '.lnk', '.com', '.pif', '.apk', '.ipa', '.sh', '.py', '.dylib', '.so', '.elf', '.bin', '.pkg', '.dmg', '.command', '.iso', '.img', '.zip', '.rar', '.7z')
$ImgExt = @('.jpg', '.jpeg', '.png', '.gif', '.heic', '.heif', '.webp', '.bmp', '.tif', '.tiff', '.raw', '.dng', '.cr2', '.nef', '.arw', '.mp4', '.mov', '.avi', '.mkv', '.3gp', '.m4v', '.wmv')
$DisguiseExt = @('', '.dat', '.tmp', '.bin', '.db', '.0', '.cache', '.txt', '.sys', '.dll')
$RemoteTools = [ordered]@{ 'anydesk' = 'AnyDesk'; 'teamviewer' = 'TeamViewer'; 'tv_w32' = 'TeamViewer'; 'tv_x64' = 'TeamViewer'; 'rustdesk' = 'RustDesk'; 'client32' = 'NetSupport Manager'; 'screenconnect' = 'ScreenConnect'; 'ateraagent' = 'Atera'; 'srservice' = 'Splashtop'; 'strwinclt' = 'Splashtop'; 'aa_v3' = 'Ammyy Admin'; 'ultraviewer' = 'UltraViewer'; 'supremo' = 'Supremo'; 'logmein' = 'LogMeIn'; 'lmiguardiansvc' = 'LogMeIn'; 'remoting_host' = 'Chrome Remote Desktop'; 'dwagent' = 'DWService'; 'tvnserver' = 'TightVNC'; 'winvnc' = 'UltraVNC'; 'vncserver' = 'VNC Server'; 'x11vnc' = 'x11vnc'; 'remotepc' = 'RemotePC'; 'zohoassist' = 'Zoho Assist'; 'meshagent' = 'MeshCentral'; 'simplehelp' = 'SimpleHelp' }
$VpnName = 'tap-windows|tap adapter|wintun|wireguard|openvpn|anyconnect|forticlient|fortinet ssl|nordlynx|nordvpn|protonvpn|proton vpn|mullvad|windscribe|expressvpn|surfshark|cyberghost|private internet access|tunnelbear|hotspot shield|globalprotect|pangp|juniper|pulse secure|ivanti|sonicwall|check ?point|zscaler|tailscale|zerotier|hamachi|softether|\bvpn\b'
$KnownResolvers = @{ '8.8.8.8' = 'Google Public DNS'; '8.8.4.4' = 'Google Public DNS'; '1.1.1.1' = 'Cloudflare'; '1.0.0.1' = 'Cloudflare'; '1.1.1.2' = 'Cloudflare (malware filter)'; '1.0.0.2' = 'Cloudflare (malware filter)'; '1.1.1.3' = 'Cloudflare (family filter)'; '1.0.0.3' = 'Cloudflare (family filter)'; '9.9.9.9' = 'Quad9'; '149.112.112.112' = 'Quad9'; '9.9.9.10' = 'Quad9'; '9.9.9.11' = 'Quad9'; '208.67.222.222' = 'OpenDNS'; '208.67.220.220' = 'OpenDNS'; '208.67.222.123' = 'OpenDNS FamilyShield'; '208.67.220.123' = 'OpenDNS FamilyShield'; '94.140.14.14' = 'AdGuard DNS'; '94.140.15.15' = 'AdGuard DNS'; '94.140.14.15' = 'AdGuard DNS (family)'; '94.140.15.16' = 'AdGuard DNS (family)'; '185.228.168.9' = 'CleanBrowsing'; '185.228.169.9' = 'CleanBrowsing'; '76.76.2.0' = 'Control D'; '76.76.10.0' = 'Control D'; '194.242.2.2' = 'Mullvad DNS'; '103.86.96.100' = 'NordVPN DNS'; '103.86.99.100' = 'NordVPN DNS'; '2001:4860:4860::8888' = 'Google Public DNS'; '2001:4860:4860::8844' = 'Google Public DNS'; '2606:4700:4700::1111' = 'Cloudflare'; '2606:4700:4700::1001' = 'Cloudflare'; '2620:fe::fe' = 'Quad9'; '2620:fe::9' = 'Quad9' }
$CertRisk = @(
    @('superfish', 'WARNING', 'Superfish - adware root certificate (Lenovo, 2015) that lets attackers read HTTPS traffic'),
    @('edellroot|dsdtestprovider', 'WARNING', 'eDellRoot - insecure root certificate shipped on Dell laptops (2015)'),
    @('komodia', 'WARNING', 'Komodia - HTTPS interception component used by adware'),
    @('privdog', 'WARNING', 'PrivDog - adware with HTTPS interception'),
    @('mitmproxy', 'WARNING', 'mitmproxy - tool that intercepts HTTPS traffic'),
    @('fiddler', 'WARNING', 'Fiddler - HTTPS debugging proxy that intercepts traffic'),
    @('charles proxy|charles ssl', 'WARNING', 'Charles Proxy - HTTPS debugging proxy that intercepts traffic'),
    @('portswigger', 'WARNING', 'Burp Suite (PortSwigger) - HTTPS interception proxy'),
    @('proxyman', 'WARNING', 'Proxyman - HTTPS debugging proxy'),
    @('http ?toolkit', 'WARNING', 'HTTP Toolkit - HTTPS interception proxy'),
    @('kaspersky|avast|\bavg\b|eset ssl|bitdefender|sophos|dr\.?web|g data|f-secure|webroot', 'INFO', 'HTTPS scanning by an antivirus program - usually intended'),
    @('zscaler|netskope|forcepoint|fortigate|palo alto|umbrella|blue ?coat|websense', 'INFO', 'Company HTTPS inspection - normal on work devices, unusual on private ones')
)
# baseline categories: name = singular, plural, severe
$BaseLabels = @{ autostart = @('autostart entry', 'autostart entries', $true); tasks = @('scheduled task', 'scheduled tasks', $true); services = @('service', 'services', $true); vpn = @('VPN connection or VPN app', 'VPN connections or VPN apps', $true); proxy = @('proxy setting', 'proxy settings', $true); certs = @('trusted root certificate', 'trusted root certificates', $true); remote = @('remote access program', 'remote access programs', $true); dns = @('DNS server', 'DNS servers', $false) }
$StateRegex = '\s*-\s*(Up|Down|Disconnected|Connected|Disabled|Not Present|Dormant)\b.*$|\s*\((active: \w+|Connected|Disconnected|Connecting|Invalid|active|up|down|unknown)\)'

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { Write-Verbose 'TLS 1.2 could not be enabled' }

# ------------------------------------------------------------------ helpers
function Write-Line([string]$Text, [string]$Color = 'Gray') {
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

function Get-CountText([int]$N, [string]$Singular, [string]$Plural = '') {
    if (-not $Plural) { $Plural = $Singular + 's' }
    if ($N -eq 1) { return "1 $Singular" }
    return [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:N0} {1}', $N, $Plural)
}

function Add-Finding {
    param([string]$Sev, [string]$Area, [string]$Title, [string]$Detail = '', [string]$Path = '', [string]$Source = '')
    $f = [pscustomobject]@{ sev = $Sev; area = $Area; title = $Title; detail = $Detail; path = $(if ($Path) { $Path } else { $null }); action = $null; source = $Source; ts = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
    $Script:Findings.Add($f)
    $map = @{ 'DETECTED' = @('[DETECTED]', 'Red'); 'WARNING' = @('[WARNING] ', 'Yellow'); 'NOT CHECKED' = @('[--]      ', 'DarkGray'); 'INFO' = @('[INFO]    ', 'Cyan'); 'OK' = @('[OK]      ', 'Green') }
    $m = $map[$Sev]
    Write-Line ("{0} {1}: {2}" -f $m[0], $Area, $Title) $m[1]
    if ($Detail -and ($Sev -eq 'DETECTED' -or $Sev -eq 'WARNING')) {
        foreach ($ln in ($Detail -split "`n" | Select-Object -First 15)) { Write-Line ('             ' + $ln) 'Gray' }
    }
}

function Invoke-Check([string]$Area, [scriptblock]$Block) {
    try { & $Block }
    catch { Add-Finding 'NOT CHECKED' $Area 'Check failed' ($_.Exception.Message) }
}

function Write-Step([string]$Text) { Write-Line ([char]0x00BB + ' ' + $Text) 'DarkCyan' }

function New-PrivateDir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Force -Path $Path | Out-Null }
    if (-not $Script:IsWin) { try { & chmod 700 $Path 2>$null } catch { Write-Verbose 'chmod failed' } }
    return $Path
}

function Save-TextUtf8([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding $false))
}

function Test-Admin {
    if (-not $Script:IsWin) { try { return ((& id -u) -eq '0') } catch { return $false } }
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# FIFOs, sockets and device files would block or fail when read: only regular, non-empty files are opened
function Test-RegularFile($File) {
    if ($File.Length -le 0) { return $false }
    if (-not $Script:IsWin) {
        $um = $File.PSObject.Properties['UnixMode']
        if ($um -and $um.Value -and -not ([string]$um.Value).StartsWith('-')) { return $false }
    }
    return $true
}

function Limit-Text([string]$Text, [int]$Max) { if ($Text.Length -gt $Max) { return $Text.Substring(0, $Max) } return $Text }

# ------------------------------------------------------------------ indicators
function Update-Indicators {
    New-PrivateDir $Script:IocDir | Out-Null
    New-PrivateDir $Script:TmpDir | Out-Null
    Write-Step 'Loading the feed list from mvt-project/mvt-indicators ...'
    $tmpIndex = Join-Path $Script:TmpDir ([IO.Path]::GetRandomFileName())
    Invoke-WebRequest -UseBasicParsing -Uri $Script:IndexUrl -OutFile $tmpIndex -TimeoutSec 60 -ErrorAction Stop
    $index = [IO.File]::ReadAllText($tmpIndex)
    Remove-Item -LiteralPath $tmpIndex -Force
    $feeds = New-Object System.Collections.Generic.List[object]
    foreach ($block in ($index -split '\n\s*-\s*\n')) {
        $n = [regex]::Match($block, '\bname:\s*(.+)'); $o = [regex]::Match($block, '\bowner:\s*(\S+)')
        $r = [regex]::Match($block, '\brepo:\s*(\S+)'); $b = [regex]::Match($block, '\bbranch:\s*(\S+)'); $p = [regex]::Match($block, '\bpath:\s*(\S+)')
        if ($n.Success -and $o.Success -and $r.Success -and $b.Success -and $p.Success) {
            $feeds.Add(@{ name = $n.Groups[1].Value.Trim(); url = "https://raw.githubusercontent.com/$($o.Groups[1].Value)/$($r.Groups[1].Value)/$($b.Groups[1].Value)/$($p.Groups[1].Value)" })
        }
    }
    foreach ($x in $Script:ExtraFeeds) { $feeds.Add($x) }
    $meta = New-Object System.Collections.Generic.List[object]
    $ok = 0
    foreach ($f in $feeds) {
        $file = [regex]::Replace(($f.url -split '/', 4)[3], '[^A-Za-z0-9]+', '_')
        if ($file.Length -gt 90) { $file = $file.Substring($file.Length - 90) }
        $file += '.stix2'
        $tmp = Join-Path $Script:TmpDir ([IO.Path]::GetRandomFileName())
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $f.url -OutFile $tmp -TimeoutSec 120 -ErrorAction Stop
            $len = (Get-Item -LiteralPath $tmp).Length
            if ($len -lt 2 -or $len -gt 64MB) { throw "unexpected size ($len bytes)" }
            $head = [IO.File]::ReadAllText($tmp).TrimStart()
            if (-not $head.StartsWith('{')) { throw 'not a JSON file' }
            Move-Item -LiteralPath $tmp -Destination (Join-Path $Script:IocDir $file) -Force
            $meta.Add([ordered]@{ name = $f.name; file = $file; url = $f.url })
            $ok++
            Write-Line ('  ok     ' + $f.name) 'Green'
        }
        catch {
            Write-Line ('  ERROR  ' + $f.name + ': ' + $_.Exception.Message) 'Yellow'
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
        }
    }
    $doc = [ordered]@{ updated = (Get-Date -Format 'yyyy-MM-dd HH:mm'); feeds = $meta.ToArray() }
    Save-TextUtf8 (Join-Path $Script:IocDir 'feeds.json') ($doc | ConvertTo-Json -Depth 4)
    Write-Line ("  $(Get-CountText $ok 'source') loaded.") 'Green'
}

function Add-IocValue([string]$Type, [string]$Value, [string]$Feed) {
    if ($Value -and -not $Script:IOC[$Type].ContainsKey($Value)) { $Script:IOC[$Type][$Value] = $Feed }
}

function Import-StixText([string]$Text, [string]$Feed) {
    $n = 0
    foreach ($pm in [regex]::Matches($Text, '"pattern"\s*:\s*"((?:[^"\\]|\\.)*)"')) {
        $pat = $pm.Groups[1].Value -replace '\\u0027', "'" -replace '\\"', '"' -replace '\\/', '/' -replace '\\\\', '\'
        foreach ($kv in [regex]::Matches($pat, "([a-z0-9\-]+:[a-z0-9_.\-']+)\s*=\s*'((?:[^'\\]|\\.)*)'", 'IgnoreCase')) {
            $k = $kv.Groups[1].Value.ToLower().Replace("'", '')
            $v = $kv.Groups[2].Value.Replace("\'", "'").Trim()
            $n++
            if ($k -like 'domain-name*') { Add-IocValue 'domain' ($v.ToLower().Trim('.')) $Feed }
            elseif ($k -like 'ipv4-addr*') { Add-IocValue 'ipv4' (($v -split '/')[0]) $Feed }
            elseif ($k -like 'file:hashes*') { if ($v.Length -eq 64) { Add-IocValue 'sha256' $v.ToLower() $Feed } }
            elseif ($k -eq 'process:name') { Add-IocValue 'process' $v $Feed }
            elseif ($k -eq 'file:path') { Add-IocValue 'file_path' $v $Feed }
            elseif ($k -eq 'app:id') { Add-IocValue 'app_id' $v.ToLower() $Feed }
            elseif ($k -like 'email-addr*') { Add-IocValue 'email' $v.ToLower() $Feed }
        }
    }
    return $n
}

function Import-Indicators {
    $names = @{}
    $metaFile = Join-Path $Script:IocDir 'feeds.json'
    if (Test-Path -LiteralPath $metaFile) {
        try { foreach ($m in ((Get-Content -LiteralPath $metaFile -Raw) | ConvertFrom-Json).feeds) { $names[$m.file] = $m.name } } catch { Write-Verbose 'feeds.json not readable' }
    }
    if (Test-Path -LiteralPath $Script:IocDir) {
        foreach ($f in Get-ChildItem -LiteralPath $Script:IocDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'feeds.json' -and ($_.Extension -eq '.stix2' -or $_.Extension -eq '.json') }) {
            $feed = $f.Name
            if ($names.ContainsKey($f.Name)) { $feed = $names[$f.Name] }
            try {
                $c = Import-StixText ([IO.File]::ReadAllText($f.FullName)) $feed
                $Script:Feeds.Add([pscustomobject]@{ Name = $feed; Count = $c })
            }
            catch { Write-Verbose "Feed $($f.Name) not readable" }
        }
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = -join ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Script:SelfTestText)) | ForEach-Object { $_.ToString('x2') })
    Add-IocValue 'sha256' $hash 'SCS self-test (harmless)'
}

function Get-IocTotal { $t = 0; foreach ($k in $Script:IOC.Keys) { $t += $Script:IOC[$k].Count }; return $t }

function Test-Domain([string]$HostName) {
    if (-not $HostName) { return $null }
    $h = $HostName.ToLower().Trim().Trim('.')
    if ($h.Contains(':') -and -not $h.StartsWith('[')) { $h = $h.Split(':')[0] }
    if ($Script:IOC.ipv4.ContainsKey($h)) { return [pscustomobject]@{ Domain = $h; Feed = $Script:IOC.ipv4[$h] } }
    $parts = $h.Split('.')
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        $cand = ($parts[$i..($parts.Length - 1)]) -join '.'
        if ($Script:IOC.domain.ContainsKey($cand)) { return [pscustomobject]@{ Domain = $cand; Feed = $Script:IOC.domain[$cand] } }
    }
    return $null
}

function Test-IocStatus {
    $total = Get-IocTotal
    if ($total -lt 10) {
        Add-Finding 'NOT CHECKED' 'Indicators' 'No indicator lists loaded' "Without the lists, Pegasus, Predator, stalkerware and similar spyware cannot be detected.`nRun the scanner once with -Update (internet connection required)."
    }
    else {
        $lines = ($Script:Feeds | ForEach-Object { '  {0,6}  {1}' -f $_.Count, $_.Name }) -join "`n"
        Add-Finding 'INFO' 'Indicators' "$(Get-CountText $total 'indicator') loaded from $(Get-CountText $Script:Feeds.Count 'source')" $lines
    }
}

# ------------------------------------------------------------------ change detection
function Set-BaselineSeen([string]$Cat) {
    if (-not $Script:Snap.ContainsKey($Cat)) { $Script:Snap[$Cat] = New-Object 'System.Collections.Generic.HashSet[string]' }
}

function Add-BaselineItem([string]$Cat, $Items) {
    Set-BaselineSeen $Cat
    foreach ($i in $Items) {
        if ($null -eq $i) { continue }
        $t = ([string]$i) -replace $StateRegex, ''
        $t = Limit-Text $t.Trim() 300
        if ($t) { [void]$Script:Snap[$Cat].Add($t) }
    }
}

function Compare-Baseline {
    if ($NoBaseline -or $Script:Snap.Count -eq 0) { return }
    New-PrivateDir $Script:BaseDir | Out-Null
    $scope = 'ps-system-' + ([regex]::Replace([Environment]::MachineName, '[^A-Za-z0-9_.-]+', '_'))
    $file = Join-Path $Script:BaseDir ($scope + '.json')
    $old = $null
    if (Test-Path -LiteralPath $file) { try { $old = (Get-Content -LiteralPath $file -Raw) | ConvertFrom-Json } catch { $old = $null } }
    $items = [ordered]@{}
    foreach ($k in ($Script:Snap.Keys | Sort-Object)) { $items[$k] = @($Script:Snap[$k] | Sort-Object) }
    if ($null -eq $old) {
        Add-Finding 'INFO' 'Changes' 'Baseline created' 'From now on every scan of this computer reports new autostart entries, services, scheduled tasks, VPNs, DNS servers, proxies and trusted certificates since this scan.'
    }
    else {
        $changes = 0
        foreach ($k in $items.Keys) {
            $prop = $old.items.PSObject.Properties[$k]
            if ($null -eq $prop) { continue }
            $before = @{}
            foreach ($i in @($prop.Value)) { $before[[string]$i] = 1 }
            $new = @($items[$k] | Where-Object { -not $before.ContainsKey([string]$_) })
            if ($new.Count -eq 0) { continue }
            $changes++
            $lab = $BaseLabels[$k]
            $sev = 'INFO'; if ($lab[2]) { $sev = 'WARNING' }
            $detail = ($new | Select-Object -First 60) -join "`n"
            if ($lab[2]) { $detail += "`n`nNew autostart entries, services, VPNs, proxies or certificates are what spyware and stalkerware typically leave behind. Check that you made each change yourself." }
            Add-Finding $sev 'Changes' ("$(Get-CountText $new.Count ('new ' + $lab[0]) ('new ' + $lab[1])) since $($old.time)") $detail
        }
        if ($changes -eq 0) { Add-Finding 'OK' 'Changes' "No changes since $($old.time)" 'No new autostart entries, services, tasks, VPNs, DNS servers, proxies or certificates.' }
    }
    $doc = [ordered]@{ time = (Get-Date -Format 'yyyy-MM-dd HH:mm'); scope = $scope; items = $items }
    Save-TextUtf8 $file ($doc | ConvertTo-Json -Depth 5)
}

# ------------------------------------------------------------------ Windows: autostart, tasks, services
function Get-ExeFromCommand([string]$Cmd) {
    if (-not $Cmd) { return '' }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
    if ($c.StartsWith('"')) { return ($c.Substring(1) -split '"', 2)[0] }
    $m = [regex]::Match($c, '(.+?\.(exe|dll|bat|cmd|ps1|vbs|js|com|scr|lnk))\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split ' ')[0]
}

function Test-AutostartEntry([string]$Area, [string]$Label, [string]$Cmd) {
    $exe = Get-ExeFromCommand $Cmd
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($Cmd -match $SuspCmd) { $reasons.Add('suspicious command line (hidden or obfuscated execution)') }
    if ($exe -and $exe -match $SuspDirs -and $exe -notmatch $MsOk) { $reasons.Add('program is located in a user or temp folder') }
    if ($exe -and $exe.ToLower().EndsWith('.exe') -and $exe.Contains(':') -and -not (Test-Path -LiteralPath $exe)) { $reasons.Add('target file is missing (leftover or disguised entry)') }
    if ($reasons.Count -gt 0) {
        $p = ''; if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) { $p = $exe }
        Add-Finding 'WARNING' $Area "Suspicious autostart: $Label" ("Command: $Cmd`nReason: " + ($reasons -join '; ') + "`n`nIf in doubt, disable it with Sysinternals Autoruns.") -Path $p
        return $true
    }
    return $false
}

function Test-Autostart {
    $keys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $item = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $entries.Add([pscustomobject]@{ Key = $k; Name = $p.Name; Value = [string]$p.Value })
        }
    }
    $flagged = 0
    foreach ($e in $entries) { if (Test-AutostartEntry 'Autostart' ("$($e.Name)  ($($e.Key))") $e.Value) { $flagged++ } }
    $wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($wl) {
        if ($wl.Shell -and ([string]$wl.Shell).Trim().ToLower() -ne 'explorer.exe') { $flagged++; Add-Finding 'WARNING' 'Autostart' 'Winlogon Shell modified' "Value: $($wl.Shell)`nNormal: explorer.exe" }
        if ($wl.Userinit -and ([string]$wl.Userinit).Trim().ToLower().TrimEnd(',') -ne 'c:\windows\system32\userinit.exe') { $flagged++; Add-Finding 'WARNING' 'Autostart' 'Winlogon Userinit modified' "Value: $($wl.Userinit)`nNormal: C:\Windows\system32\userinit.exe," }
    }
    foreach ($ifeo in Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue) {
        $d = (Get-ItemProperty -LiteralPath $ifeo.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($d) { $flagged++; Add-Finding 'WARNING' 'Autostart' "Program redirect (Debugger) for $($ifeo.PSChildName)" "When $($ifeo.PSChildName) starts, this runs instead:`n$d`nMalware uses this to hijack programs." }
    }
    foreach ($folder in @((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'))) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($f in Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue) {
            if ($f.Name -eq 'desktop.ini') { continue }
            $entries.Add([pscustomobject]@{ Key = $folder; Name = $f.Name; Value = $f.FullName })
            if (@('.vbs', '.js', '.bat', '.cmd', '.ps1', '.hta', '.exe', '.scr') -contains $f.Extension.ToLower()) {
                $flagged++; Add-Finding 'WARNING' 'Autostart' "Script or program in the Startup folder: $($f.Name)" $f.FullName -Path $f.FullName
            }
        }
    }
    Add-BaselineItem 'autostart' ($entries | ForEach-Object { "$($_.Name) = $($_.Value)" })
    $lines = ($entries | Select-Object -First 80 | ForEach-Object { '{0,-30} {1}' -f (Limit-Text $_.Name 30), $_.Value }) -join "`n"
    $sev = 'INFO'; if ($flagged) { $sev = 'WARNING' }
    Add-Finding $sev 'Autostart' "$(Get-CountText $entries.Count 'autostart entry' 'autostart entries'), $flagged suspicious" $lines
}

function Test-Tasks {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' })
    $flagged = 0
    Set-BaselineSeen 'tasks'
    foreach ($t in $tasks) {
        $name = "$($t.TaskPath)$($t.TaskName)"
        if ($name -like '\Microsoft\*') { continue }
        $cmd = (@($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ').Trim()
        if (-not $cmd) { continue }
        Add-BaselineItem 'tasks' "$name -> $cmd"
        if (Test-AutostartEntry 'Scheduled tasks' $name $cmd) { $flagged++ }
    }
    $sev = 'OK'; if ($flagged) { $sev = 'WARNING' }
    Add-Finding $sev 'Scheduled tasks' "$(Get-CountText $tasks.Count 'active task') checked, $flagged suspicious"
}

function Test-Services {
    $svc = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    $flagged = 0
    Set-BaselineSeen 'services'
    foreach ($s in $svc) {
        $path = [string]$s.PathName
        if ($s.StartMode -eq 'Disabled' -or -not $path) { continue }
        if ($path -match '\\windows\\system32\\svchost\.exe') { continue }
        Add-BaselineItem 'services' "$($s.Name): $path"
        if (Test-AutostartEntry 'Services' "$($s.DisplayName) ($($s.Name))" $path) { $flagged++ }
    }
    $sev = 'OK'; if ($flagged) { $sev = 'WARNING' }
    Add-Finding $sev 'Services' "$(Get-CountText $svc.Count 'service') checked, $flagged suspicious"
}

# ------------------------------------------------------------------ processes
function Get-ProcessList {
    if ($Script:IsWin) {
        $Script:Procs = @(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Id = $_.ProcessId; Name = [string]$_.Name; Path = [string]$_.ExecutablePath; Cmd = [string]$_.CommandLine } })
    }
    else {
        $Script:Procs = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Name = [string]$_.ProcessName; Path = [string]$_.Path; Cmd = '' } })
    }
}

function Test-Processes {
    Get-ProcessList
    if ($Script:Procs.Count -eq 0) { Add-Finding 'NOT CHECKED' 'Processes' 'Process list not available'; return }
    foreach ($p in $Script:Procs) {
        if ($p.Id -eq $PID -or $p.Cmd -match 'scs\.ps1|scs-scanner') { continue }
        if ($p.Cmd -and $p.Cmd -match $SuspCmd) { Add-Finding 'WARNING' 'Processes' "Suspicious command line: $($p.Name) (PID $($p.Id))" (Limit-Text $p.Cmd 1500) }
        elseif ($p.Path -and $p.Path -match '\\(temp|tmp|users\\public|\$recycle\.bin)\\' -and $p.Path -notmatch $MsOk) { Add-Finding 'WARNING' 'Processes' "Program running from a temp folder: $($p.Name)" $p.Path -Path $p.Path }
    }
    $hits = 0
    $seen = @{}
    Set-BaselineSeen 'remote'
    foreach ($p in $Script:Procs) {
        $base = [IO.Path]::GetFileNameWithoutExtension($p.Name)
        $feed = $null
        if ($Script:IOC.process.ContainsKey($p.Name)) { $feed = $Script:IOC.process[$p.Name] } elseif ($Script:IOC.process.ContainsKey($base)) { $feed = $Script:IOC.process[$base] }
        if ($feed) { $hits++; Add-Finding 'DETECTED' 'Processes' "Running process matches spyware: $($p.Name)" "PID $($p.Id)  Path: $($p.Path)`nSource: $feed" -Path $p.Path -Source $feed }
        $key = $base.ToLower()
        foreach ($rt in $RemoteTools.GetEnumerator()) {
            if ($key -eq $rt.Key -or ($rt.Key.Length -gt 5 -and $key.StartsWith($rt.Key))) {
                if (-not $seen.ContainsKey($rt.Value)) {
                    $seen[$rt.Value] = 1
                    Add-BaselineItem 'remote' $rt.Value
                    Add-Finding 'WARNING' 'Remote access' "Remote access program running: $($rt.Value)" "Process: $($p.Name)  Path: $($p.Path)`nLegitimate software, but often abused by scammers (fake 'Microsoft support') and stalkers. If you did not install it yourself: quit it, uninstall it and change your passwords."
                }
                break
            }
        }
    }
    $t = "$(Get-CountText $Script:Procs.Count 'process' 'processes') checked"
    if ($hits) { $t += ", $(Get-CountText $hits 'hit')" }
    Add-Finding 'OK' 'Processes' $t
}

function Test-Signatures {
    $paths = @($Script:Procs | Where-Object { $_.Path -and $_.Path -notmatch '^c:\\windows\\' } | ForEach-Object { $_.Path } | Sort-Object -Unique | Select-Object -First 400)
    if ($paths.Count -eq 0) { return }
    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($p in $paths) {
        try { $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; if ([string]$s.Status -ne 'Valid') { $bad.Add(('{0,-14} {1}' -f [string]$s.Status, $p)) } } catch { Write-Verbose "No signature check for $p" }
    }
    if ($bad.Count) { Add-Finding 'WARNING' 'Signatures' "$(Get-CountText $bad.Count 'running program') without a valid signature" ("Unsigned programs are not automatically malicious (many hobby tools are unsigned), but you should recognise each one:`n" + (($bad | Select-Object -First 80) -join "`n")) }
    Add-Finding 'OK' 'Signatures' "$(Get-CountText $paths.Count 'program') checked for a valid signature"
}

# ------------------------------------------------------------------ VPN, proxy, DNS servers, certificates
function Get-IpKind([string]$Ip) {
    $raw = $Ip.Split('%')[0].Trim()
    $a = $null
    if (-not [System.Net.IPAddress]::TryParse($raw, [ref]$a)) { return @('unknown', 'not an IP address') }
    if ([System.Net.IPAddress]::IsLoopback($a)) { return @('local', 'resolver on this device (e.g. VPN client, ad blocker)') }
    $b = $a.GetAddressBytes()
    if ($b.Length -eq 4) {
        if ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 169 -and $b[1] -eq 254)) { return @('local', 'local network (router) or VPN') }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return @('local', 'carrier-grade NAT / VPN range (e.g. Tailscale)') }
    }
    else {
        if (($b[0] -band 0xFE) -eq 0xFC -or ($b[0] -eq 0xFE -and ($b[1] -band 0xC0) -eq 0x80)) { return @('local', 'local network (router) or VPN') }
    }
    if ($KnownResolvers.ContainsKey($raw)) { return @('known', $KnownResolvers[$raw]) }
    if ($raw.StartsWith('45.90.28.') -or $raw.StartsWith('45.90.30.')) { return @('known', 'NextDNS') }
    return @('unknown', 'unknown public server')
}

function Test-Routing {
    $active = New-Object System.Collections.Generic.List[string]
    $configured = New-Object System.Collections.Generic.List[string]
    $servers = New-Object System.Collections.Generic.List[object]
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
        $label = "$($a.Name) ($($a.InterfaceDescription))"
        if ($label -match $VpnName -and $label -notmatch 'miniport') {
            $configured.Add("Adapter: $label - $($a.Status)")
            if ([string]$a.Status -eq 'Up') { $active.Add([string]$a.Name) }
        }
    }
    $profiles = @()
    try { $profiles += @(Get-VpnConnection -ErrorAction Stop) } catch { Write-Verbose 'no user VPN profiles' }
    try { $profiles += @(Get-VpnConnection -AllUserConnection -ErrorAction Stop) } catch { Write-Verbose 'no all-user VPN profiles' }
    foreach ($p in $profiles) {
        $configured.Add("Windows VPN profile: $($p.Name) -> $($p.ServerAddress) ($($p.TunnelType), $($p.ConnectionStatus))")
        $servers.Add($p)
        if ([string]$p.ConnectionStatus -eq 'Connected') { $active.Add([string]$p.Name) }
    }
    $Script:Vpn = @($active | Select-Object -Unique)
    Set-BaselineSeen 'vpn'
    Add-BaselineItem 'vpn' $configured
    if ($Script:Vpn.Count) {
        Add-Finding 'INFO' 'VPN' ("VPN active: " + ($Script:Vpn -join ', ')) ("Traffic is routed through a VPN tunnel. What that means for this scan:`n- Active connections show the VPN server, not the real destinations - the connection check is limited.`n- Name lookups made by the VPN app itself (e.g. DNS-over-HTTPS) do not appear in the DNS history.`n- On-device checks (autostart, processes, files, browser history) are not affected.`n`nA VPN provider can see and redirect your traffic. Only use VPN apps you installed yourself from a trustworthy source.")
    }
    if ($configured.Count) { Add-Finding 'INFO' 'VPN' "$(Get-CountText $configured.Count 'VPN connection or VPN app' 'VPN connections or VPN apps') configured" ("Check that you set up each of these yourself:`n" + ($configured -join "`n")) }
    elseif (-not $Script:Vpn.Count) { Add-Finding 'OK' 'VPN' 'No VPN active or configured' }
    foreach ($p in $servers) {
        $r = Test-Domain ([string]$p.ServerAddress)
        if ($r) { Add-Finding 'DETECTED' 'VPN' "VPN server is a known spyware address: $($p.ServerAddress)" "VPN profile: $($p.Name)`nAll traffic of this computer can be read by that server." -Source $r.Feed }
    }

    # proxy
    $proxies = New-Object System.Collections.Generic.List[object]
    $is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($is) {
        if ($is.ProxyEnable -eq 1 -and $is.ProxyServer) { $proxies.Add(@('System proxy', [string]$is.ProxyServer)) }
        if ($is.AutoConfigURL) { $proxies.Add(@('Proxy auto-config script (PAC)', [string]$is.AutoConfigURL)) }
    }
    foreach ($v in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')) { $val = [Environment]::GetEnvironmentVariable($v); if ($val) { $proxies.Add(@("Environment variable $v", $val)) } }
    Set-BaselineSeen 'proxy'
    if ($proxies.Count -eq 0) { Add-Finding 'OK' 'Proxy' 'No proxy configured' }
    foreach ($px in $proxies) {
        Add-BaselineItem 'proxy' ("$($px[0]): $($px[1])")
        $hostPart = ([string]$px[1]) -replace '^[a-z]+://', '' -replace '[:/].*$', ''
        $r = Test-Domain $hostPart
        if ($r) { Add-Finding 'DETECTED' 'Proxy' "$($px[0]) points to a known spyware address: $hostPart" "Value: $($px[1])" -Source $r.Feed; continue }
        Add-Finding 'WARNING' 'Proxy' "$($px[0]) configured: $($px[1])" 'All web traffic is sent through this server. That is normal in some companies and with some security or VPN tools; otherwise it is a classic trick of banking trojans and adware to read or alter traffic.'
    }

    # DNS servers
    Set-BaselineSeen 'dns'
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($d in @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses })) {
        $iface = [string]$d.InterfaceAlias
        if ($iface -match '^(loopback pseudo|isatap)') { continue }
        foreach ($ip in @($d.ServerAddresses)) {
            $ip = [string]$ip
            if ($ip.ToLower().StartsWith('fec0:0:0:ffff')) { continue }
            Add-BaselineItem 'dns' "$ip ($iface)"
            if ($Script:IOC.ipv4.ContainsKey($ip)) { Add-Finding 'DETECTED' 'DNS servers' "DNS server is a known spyware address: $ip" "Interface: $iface" -Source $Script:IOC.ipv4[$ip]; continue }
            $kind = Get-IpKind $ip
            $onVpn = ($iface -match $VpnName) -or ($Script:Vpn -contains $iface)
            $desc = $kind[1]; if ($onVpn) { $desc += ' - provided by the VPN' }
            $lines.Add(('{0,-40} {1,-28} {2}' -f $ip, $iface, $desc))
            if ($kind[0] -eq 'unknown' -and -not $ip.Contains(':') -and -not $onVpn) {
                Add-Finding 'WARNING' 'DNS servers' "Unknown DNS server: $ip" "Interface: $iface`n$desc`n`nThis server answers all name lookups of the computer. If neither you, your internet provider nor your VPN set it, malware may have changed it (DNS hijacking, e.g. DNSChanger). Check the DNS settings of the network adapter."
            }
        }
    }
    Add-Finding 'INFO' 'DNS servers' "$(Get-CountText $lines.Count 'DNS server entry' 'DNS server entries') configured" (('{0,-40} {1,-28} {2}' -f 'Address', 'Interface', 'Type') + "`n" + ($lines -join "`n"))

    # root certificates
    Set-BaselineSeen 'certs'
    $subjects = @(Get-ChildItem -Path 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Subject })
    $hits = 0
    foreach ($s in $subjects) {
        Add-BaselineItem 'certs' $s
        foreach ($cr in $CertRisk) {
            if ($s -match $cr[0]) { $hits++; Add-Finding $cr[1] 'Root certificates' ("Root certificate for HTTPS interception: " + (Limit-Text $s 90)) ($cr[2] + ".`nA trusted interception certificate lets the holder read encrypted (HTTPS) traffic. If you do not recognise it, remove it (certmgr.msc)."); break }
        }
    }
    if ($hits -eq 0) { Add-Finding 'OK' 'Root certificates' "$(Get-CountText $subjects.Count 'trusted root certificate') checked, none known for interception" }
}

# ------------------------------------------------------------------ DNS history, network, Defender, recycle bin
function Test-DnsHistory {
    $names = @(Get-DnsClientCache -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Entry } | Sort-Object -Unique)
    $hits = @{}
    foreach ($n in $names) { $r = Test-Domain $n; if ($r -and -not $hits.ContainsKey($r.Domain)) { $hits[$r.Domain] = 1; Add-Finding 'DETECTED' 'DNS' "Known spyware address: $($r.Domain)" "Found in: Windows DNS cache (recent name lookups)`nName: $n`n`nThis alone does not prove an infection, but it is a serious warning sign. Save the report and consult experts." -Source $r.Feed } }
    $note = ''; if ($Script:Vpn.Count) { $note = 'VPN active: name lookups made by the VPN app itself are not recorded here.' }
    Add-Finding 'OK' 'DNS' "$(Get-CountText $names.Count 'DNS cache entry' 'DNS cache entries') checked" $note
    $max = 30000; if ($Mode -eq 'Full') { $max = 200000 }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Id = 3006, 3008 } -MaxEvents $max -ErrorAction Stop)
    }
    catch {
        Add-Finding 'NOT CHECKED' 'DNS' 'DNS history (event log) not available' ($_.Exception.Message + "`n`nTip: enable it as administrator so that future lookups are recorded:`nwevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true")
        return
    }
    $q = @{}
    foreach ($e in $events) { try { $q[[string]$e.Properties[0].Value] = 1 } catch { Write-Verbose 'event without name' } }
    foreach ($n in $q.Keys) { $r = Test-Domain $n; if ($r -and -not $hits.ContainsKey($r.Domain)) { $hits[$r.Domain] = 1; Add-Finding 'DETECTED' 'DNS' "Known spyware address: $($r.Domain)" "Found in: DNS client event log (history)`nName: $n" -Source $r.Feed } }
    Add-Finding 'OK' 'DNS' "$(Get-CountText $q.Count 'stored DNS query' 'stored DNS queries') checked" $note
}

function Test-Connections {
    $ips = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.RemoteAddress } | Sort-Object -Unique)
    $hits = 0
    foreach ($ip in $ips) { if ($Script:IOC.ipv4.ContainsKey($ip)) { $hits++; Add-Finding 'DETECTED' 'Network' "Connection to known spyware IP $ip" '' -Source $Script:IOC.ipv4[$ip] } }
    $t = "$(Get-CountText $ips.Count 'remote host') (active TCP connections) checked"
    $note = ''
    if ($Script:Vpn.Count) { $t += ' - limited by VPN'; $note = "A VPN is active ($($Script:Vpn -join ', ')): connections inside the tunnel are not visible here, only the VPN server and traffic outside the tunnel." }
    Add-Finding 'OK' 'Network' $t $note
}

function Test-Defender {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $probs = New-Object System.Collections.Generic.List[string]
    if (-not $s.AntivirusEnabled) { $probs.Add('antivirus off') }
    if (-not $s.RealTimeProtectionEnabled) { $probs.Add('real-time protection off') }
    if ($s.AntivirusSignatureAge -gt 7) { $probs.Add("signatures $($s.AntivirusSignatureAge) days old") }
    if ($s.IsTamperProtected -eq $false) { $probs.Add('tamper protection off') }
    if ($probs.Count) { Add-Finding 'WARNING' 'Defender' ('Defender: ' + ($probs -join ', ')) 'Malware likes to switch Defender off. Settings > Windows Security > Virus & threat protection.' }
    else { Add-Finding 'OK' 'Defender' 'Defender: active and up to date' }
    if (Test-Admin) {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($k in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension')) { foreach ($x in @($pref.$k)) { if ($x) { $items.Add("${k}: $x") } } }
        if ($items.Count) { Add-Finding 'WARNING' 'Defender' "$(Get-CountText $items.Count 'exclusion') configured in Defender" ("Malware adds itself here to avoid being scanned:`n" + ($items -join "`n")) }
    }
    else { Add-Finding 'NOT CHECKED' 'Defender' 'Defender exclusions not checkable' 'Readable with administrator rights only.' }
}

function Get-RecycleBinCount { return (New-Object -ComObject Shell.Application).NameSpace(10).Items().Count }

function Test-RecycleBin {
    $n = Get-RecycleBinCount
    if ($n) { Add-Finding 'INFO' 'Recycle Bin' "$(Get-CountText $n 'item') in the Recycle Bin" 'Deleted files in the Recycle Bin can be fully restored.' }
}

function Get-AltStreams($Dirs) {
    $skip = @(':$DATA', 'Zone.Identifier', 'SmartScreen', 'com.dropbox.attrs', 'ms-properties')
    return @(Get-ChildItem -LiteralPath $Dirs -Recurse -File -Force -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object { $skip -notcontains $_.Stream })
}

function Test-Ads {
    $dirs = @('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos') | ForEach-Object { Join-Path $Script:UserHome $_ } | Where-Object { Test-Path -LiteralPath $_ }
    $rows = @(Get-AltStreams $dirs)
    if ($rows.Count) { Add-Finding 'WARNING' 'Hidden data streams' "$(Get-CountText $rows.Count 'hidden data stream') (ADS) found" ("Data that is invisibly attached to ordinary files:`n" + (($rows | Select-Object -First 80 | ForEach-Object { '{0,10}  {1}:{2}' -f $_.Length, $_.FileName, $_.Stream }) -join "`n") + "`n`nView a stream: Get-Content -Path FILE -Stream NAME") }
    else { Add-Finding 'OK' 'Hidden data streams' 'No hidden data streams in the user folders' }
}

# ------------------------------------------------------------------ cross-platform checks
function Test-Hosts {
    $p = '/etc/hosts'; if ($Script:IsWin) { $p = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts' }
    if (-not (Test-Path -LiteralPath $p)) { return }
    $normal = @('localhost', 'ip6-localhost', 'ip6-loopback', 'broadcasthost', 'ip6-allnodes', 'ip6-allrouters', 'ip6-localnet', 'ip6-mcastprefix')
    $odd = @(Get-Content -LiteralPath $p -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | Where-Object {
            $parts = $_ -split '\s+'
            $names = @($parts | Select-Object -Skip 1)
            ($parts[0] -ne '127.0.1.1') -and (@($names | Where-Object { $normal -notcontains $_ }).Count -gt 0)
        })
    if ($odd.Count) { Add-Finding 'WARNING' 'Network' "hosts file contains $(Get-CountText $odd.Count 'redirect')" ("$p`n" + (($odd | Select-Object -First 40) -join "`n") + "`n`nMalware uses this file to redirect banking or update sites. Entries added by ad blockers you installed yourself are harmless.") }
    else { Add-Finding 'OK' 'Network' 'hosts file looks normal' }
}

function Test-IocPaths {
    $hits = 0
    foreach ($raw in @($Script:IOC.file_path.Keys)) {
        $p = [Environment]::ExpandEnvironmentVariables($raw)
        if ($Script:IsWin) { if ($p.Length -lt 3 -or $p[1] -ne ':') { continue } }
        else { if (-not $p.StartsWith('/') -or $p.StartsWith('/private/var/mobile') -or $p.StartsWith('/data/')) { continue } }
        if (Test-Path -LiteralPath $p) { $hits++; Add-Finding 'DETECTED' 'Traces' "Known spyware file present: $(Split-Path $p -Leaf)" $p -Path $p -Source $Script:IOC.file_path[$raw] }
    }
    if ($hits -eq 0) { Add-Finding 'OK' 'Traces' 'No known spyware file paths found' }
}

function Get-BrowserFiles {
    $list = New-Object System.Collections.Generic.List[object]
    $chromium = @{}
    $firefox = @()
    if ($Script:IsWin) {
        $L = $env:LOCALAPPDATA; $R = $env:APPDATA
        $chromium = [ordered]@{ 'Chrome' = "$L\Google\Chrome\User Data"; 'Edge' = "$L\Microsoft\Edge\User Data"; 'Brave' = "$L\BraveSoftware\Brave-Browser\User Data"; 'Vivaldi' = "$L\Vivaldi\User Data"; 'Chromium' = "$L\Chromium\User Data"; 'Opera' = "$R\Opera Software" }
        $firefox = @("$R\Mozilla\Firefox\Profiles")
    }
    elseif (Test-Path -LiteralPath (Join-Path $Script:UserHome 'Library')) {
        $AS = Join-Path $Script:UserHome 'Library/Application Support'
        $chromium = [ordered]@{ 'Chrome' = "$AS/Google/Chrome"; 'Edge' = "$AS/Microsoft Edge"; 'Brave' = "$AS/BraveSoftware/Brave-Browser"; 'Vivaldi' = "$AS/Vivaldi" }
        $firefox = @("$AS/Firefox/Profiles")
        $safari = Join-Path $Script:UserHome 'Library/Safari/History.db'
        if (Test-Path -LiteralPath $safari) { $list.Add([pscustomobject]@{ Name = 'Safari'; Path = $safari }) }
    }
    else {
        $C = Join-Path $Script:UserHome '.config'
        $chromium = [ordered]@{ 'Chrome' = "$C/google-chrome"; 'Chromium' = "$C/chromium"; 'Brave' = "$C/BraveSoftware/Brave-Browser"; 'Edge' = "$C/microsoft-edge"; 'Vivaldi' = "$C/vivaldi" }
        $firefox = @((Join-Path $Script:UserHome '.mozilla/firefox'), (Join-Path $Script:UserHome 'snap/firefox/common/.mozilla/firefox'))
    }
    foreach ($b in $chromium.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $b.Value)) { continue }
        foreach ($d in Get-ChildItem -LiteralPath $b.Value -Directory -ErrorAction SilentlyContinue) {
            $h = Join-Path $d.FullName 'History'
            if (Test-Path -LiteralPath $h -PathType Leaf) { $list.Add([pscustomobject]@{ Name = $b.Key; Path = $h }) }
        }
    }
    foreach ($ff in $firefox) {
        if (-not (Test-Path -LiteralPath $ff)) { continue }
        foreach ($d in Get-ChildItem -LiteralPath $ff -Directory -ErrorAction SilentlyContinue) {
            $h = Join-Path $d.FullName 'places.sqlite'
            if (Test-Path -LiteralPath $h -PathType Leaf) { $list.Add([pscustomobject]@{ Name = 'Firefox'; Path = $h }) }
        }
    }
    return $list.ToArray()
}

function Test-Browsers {
    New-PrivateDir $Script:TmpDir | Out-Null
    $files = @(Get-BrowserFiles)
    if ($files.Count -eq 0) { Add-Finding 'INFO' 'Browser' 'No browser history found'; return }
    foreach ($bf in $files) {
        $name = $bf.Name; $path = $bf.Path
        $tmp = Join-Path $Script:TmpDir ([IO.Path]::GetRandomFileName())
        try { Copy-Item -LiteralPath $path -Destination $tmp -Force -ErrorAction Stop }
        catch { Add-Finding 'NOT CHECKED' 'Browser' "${name}: history not readable" "$path`nClose the browser and try again. On a Mac, grant Full Disk Access to the terminal."; continue }
        try { $bytes = [IO.File]::ReadAllBytes($tmp) } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        $text = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
        $hosts = @{}
        foreach ($m in [regex]::Matches($text, 'https?://([A-Za-z0-9.\-]{3,253})')) { $hosts[$m.Groups[1].Value.ToLower()] = 1 }
        foreach ($h in $hosts.Keys) {
            $r = Test-Domain $h
            if ($r) { Add-Finding 'DETECTED' 'Browser' "Known spyware address: $($r.Domain)" "Found in: $name history ($path)`nAddress: $h`n`nThe address appears in the browser history - deleted entries are found too. This alone does not prove an infection, but it is a serious warning sign." -Source $r.Feed }
        }
        Add-Finding 'OK' 'Browser' "${name}: $(Get-CountText $hosts.Count 'web address' 'web addresses') checked" $path
    }
}

function Get-RiskyDirs {
    if ($Script:IsWin) {
        $d = @((Join-Path $Script:UserHome 'Downloads'), (Join-Path $Script:UserHome 'Desktop'), $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData, 'C:\Users\Public',
            (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'), (Join-Path $env:SystemRoot 'Temp'))
    }
    elseif (Test-Path -LiteralPath (Join-Path $Script:UserHome 'Library')) {
        $d = @((Join-Path $Script:UserHome 'Downloads'), (Join-Path $Script:UserHome 'Library/LaunchAgents'), '/Library/LaunchAgents', '/Library/LaunchDaemons', '/tmp', '/private/var/tmp', '/Users/Shared')
    }
    else {
        $d = @((Join-Path $Script:UserHome 'Downloads'), '/tmp', '/var/tmp', '/dev/shm', (Join-Path $Script:UserHome '.local/bin'), (Join-Path $Script:UserHome '.config'), '/opt', '/usr/local/bin')
    }
    $d += (Join-Path $Script:DataDir 'selftest')
    return @($d | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
}

function Test-Hashes {
    $max = 3000; $maxBytes = 25MB; $depth = 4
    if ($Mode -eq 'Full') { $max = 40000; $maxBytes = 150MB; $depth = 8 }
    $n = 0; $hits = 0
    $seen = @{}   # the folders overlap (AppData and the Startup folder inside it): check every file once
    $dirs = Get-RiskyDirs
    foreach ($d in $dirs) {
        if ($n -ge $max) { break }
        $files = @(Get-ChildItem -LiteralPath $d -Recurse -Depth $depth -File -Force -ErrorAction SilentlyContinue |
                Where-Object { ($Mode -eq 'Full') -or ($ExecExt -contains $_.Extension.ToLower()) -or ($_.Name -like 'SCS-SELFTEST*') } |
                Where-Object { $_.Length -le $maxBytes -and -not $_.Name.EndsWith('.quarantined') -and (Test-RegularFile $_) } | Select-Object -First ($max - $n))
        foreach ($f in $files) {
            if ($seen.ContainsKey($f.FullName)) { continue }
            $seen[$f.FullName] = 1
            $n++
            $h = $null
            try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { continue }
            if ($Script:IOC.sha256.ContainsKey($h)) { $hits++; Add-Finding 'DETECTED' 'Files' "Known malware: $($f.Name)" "$($f.FullName)`nSHA-256: $h`nTo quarantine it: -Quarantine `"$($f.FullName)`"" -Path $f.FullName -Source $Script:IOC.sha256[$h] }
        }
    }
    Add-Finding 'OK' 'Files' "$(Get-CountText $n 'file') checked by fingerprint (SHA-256)" ("Folders checked:`n" + ($dirs -join "`n"))
}

function Get-MagicKind([string]$Path) {
    $buf = New-Object byte[] 16
    try { $fs = [IO.File]::OpenRead($Path); try { $r = $fs.Read($buf, 0, 16) } finally { $fs.Close() } } catch { return $null }
    if ($r -lt 12) { return $null }
    if ($buf[4] -eq 0x66 -and $buf[5] -eq 0x74 -and $buf[6] -eq 0x79 -and $buf[7] -eq 0x70) {
        $brand = [Text.Encoding]::ASCII.GetString($buf, 8, 4)
        if (@('heic', 'heix', 'mif1', 'heim') -contains $brand) { return 'HEIC image' }
        return 'Video (MP4/MOV)'
    }
    if ($buf[0] -eq 0xFF -and $buf[1] -eq 0xD8 -and $buf[2] -eq 0xFF) { return 'JPEG image' }
    if ($buf[0] -eq 0x89 -and $buf[1] -eq 0x50 -and $buf[2] -eq 0x4E -and $buf[3] -eq 0x47) { return 'PNG image' }
    if ($buf[0] -eq 0x47 -and $buf[1] -eq 0x49 -and $buf[2] -eq 0x46 -and $buf[3] -eq 0x38) { return 'GIF image' }
    if ($buf[0] -eq 0x52 -and $buf[1] -eq 0x49 -and $buf[2] -eq 0x46 -and $buf[3] -eq 0x46) {
        $t = [Text.Encoding]::ASCII.GetString($buf, 8, 4)
        if ($t -eq 'WEBP' -or $t -eq 'AVI ') { return 'RIFF (WebP/AVI)' }
    }
    return $null
}

function Get-TrailingData([string]$Path) {
    $data = [IO.File]::ReadAllBytes($Path)
    $len = $data.Length
    $end = -1
    if ($len -gt 8 -and $data[0] -eq 0xFF -and $data[1] -eq 0xD8) {
        $i = [Array]::LastIndexOf($data, [byte]0xD9)
        while ($i -gt 1 -and $data[$i - 1] -ne 0xFF) { $i = [Array]::LastIndexOf($data, [byte]0xD9, $i - 1) }
        if ($i -gt 1) { $end = $i + 1 }
    }
    elseif ($len -gt 8 -and $data[0] -eq 0x89 -and $data[1] -eq 0x50) {
        $s = [Text.Encoding]::GetEncoding(28591).GetString($data)
        $i = $s.LastIndexOf('IEND')
        if ($i -gt 0) { $end = $i + 8 }
    }
    if ($end -lt 0) { return $null }
    $extra = $len - $end
    if ($extra -lt 2048) { return $null }
    $tail = [Text.Encoding]::GetEncoding(28591).GetString($data, $end, [Math]::Min(64, $extra))
    $kind = 'unknown appended data'
    if ($tail.Substring(0, [Math]::Min(16, $tail.Length)).Contains('ftyp')) { $kind = 'an appended video (Motion Photo - usually harmless)' }
    elseif ($tail.StartsWith("PK$([char]3)$([char]4)")) { $kind = 'an appended ZIP archive' }
    elseif ($tail.StartsWith('Rar!')) { $kind = 'an appended RAR archive' }
    elseif ($tail.StartsWith('MZ')) { $kind = 'an appended Windows program' }
    return @($extra, $kind)
}

function Test-HiddenImages {
    $depth = 6; $max = 60000
    if ($Mode -eq 'Full') { $depth = 12; $max = 300000 }
    $hidden = New-Object System.Collections.Generic.List[string]
    $disguised = New-Object System.Collections.Generic.List[string]
    $cacheDirs = @{}
    $n = 0
    $homeLen = $Script:UserHome.Length
    Get-ChildItem -LiteralPath $Script:UserHome -Recurse -Depth $depth -File -Force -ErrorAction SilentlyContinue | Select-Object -First $max | ForEach-Object {
        $n++
        $f = $_
        if (-not (Test-RegularFile $f) -or $f.Name.EndsWith('.quarantined')) { return }
        $ext = $f.Extension.ToLower()
        $full = $f.FullName
        $low = $full.ToLower()
        if ($low -match '[\\/](node_modules|\.git|__pycache__|site-packages)[\\/]') { return }
        $isCache = $low -match 'cache|thumbnail|[\\/]temp[\\/]|[\\/]tmp[\\/]'
        $rel = ''; if ($full.Length -gt $homeLen) { $rel = $full.Substring($homeLen) }
        $inHiddenDir = $rel -match '[\\/]\.[^\\/]+[\\/]'
        $isHidden = (($f.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) -or $f.Name.StartsWith('.')
        if ($ImgExt -contains $ext) {
            if ($isHidden -or $inHiddenDir) { if ($isCache) { $cacheDirs[$f.DirectoryName] = 1 + [int]$cacheDirs[$f.DirectoryName] } else { $hidden.Add($full) } }
            if ($Mode -eq 'Full' -and ($ext -eq '.jpg' -or $ext -eq '.jpeg' -or $ext -eq '.png') -and $f.Length -le 15MB) {
                $t = Get-TrailingData $full
                if ($t) {
                    if ($t[1] -like '*harmless*') { Add-Finding 'INFO' 'Hidden images' "Image with $($t[1])" "$full`n$($t[0]) bytes of extra data after the end of the image." -Path $full }
                    else { Add-Finding 'WARNING' 'Hidden images' "Image with $($t[1])" "$full`n$($t[0]) bytes of extra data after the end of the image.`nUse 7-Zip or binwalk to inspect what is attached." -Path $full }
                }
            }
        }
        elseif ($f.Length -gt 1500 -and $f.Length -lt 80MB -and (($Mode -eq 'Full') -or ($DisguiseExt -contains $ext))) {
            $kind = Get-MagicKind $full
            if ($kind) { if ($isCache) { $cacheDirs[$f.DirectoryName] = 1 + [int]$cacheDirs[$f.DirectoryName] } else { $disguised.Add(('{0,-16} {1}' -f $kind, $full)) } }
        }
    }
    if ($hidden.Count) { Add-Finding 'INFO' 'Hidden images' "$(Get-CountText $hidden.Count 'hidden image/video file')" ("Files with the hidden attribute or inside hidden folders (excerpt):`n" + (($hidden | Select-Object -First 60) -join "`n")) }
    if ($disguised.Count) { Add-Finding 'WARNING' 'Hidden images' "$(Get-CountText $disguised.Count 'disguised image file') (wrong file extension)" ("By their content these files are images or videos, but they carry a different extension - typical of vault apps or deliberately hidden photos:`n" + (($disguised | Select-Object -First 60) -join "`n")) }
    if ($cacheDirs.Count) {
        $top = $cacheDirs.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 25
        Add-Finding 'INFO' 'Hidden images' "Images in $(Get-CountText $cacheDirs.Count 'cache folder')" ("Viewed or deleted images often remain in caches (count - folder):`n" + (($top | ForEach-Object { '{0,7}  {1}' -f $_.Value, $_.Key }) -join "`n"))
    }
    Add-Finding 'OK' 'Hidden images' "$(Get-CountText $n 'file') searched"
}

function Test-ThumbCache {
    if (-not $Script:IsWin) { return }
    $base = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'
    $files = @(Get-ChildItem -LiteralPath $base -Filter 'thumbcache_*.db' -Force -ErrorAction SilentlyContinue)
    if ($files.Count) {
        $size = ($files | Measure-Object -Property Length -Sum).Sum
        Add-Finding 'INFO' 'Thumbnail caches' ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'Windows thumbnail cache: {0:N1} MB in {1}', ($size / 1MB), (Get-CountText $files.Count 'file'))) "$base`nThumbnails are stored here - often also of photos that were deleted long ago. Clear them with Disk Cleanup > Thumbnails."
    }
}

# ------------------------------------------------------------------ quarantine
function Get-QuarantineDir([string]$Id) {
    if (-not $Id -or $Id -notmatch '^[A-Za-z0-9._-]{1,120}$' -or $Id.Contains('..')) { throw "Invalid quarantine ID: $Id" }
    $d = Join-Path $Script:QDir $Id
    if (-not (Test-Path -LiteralPath (Join-Path $d 'info.json'))) { throw "No quarantine entry with the ID $Id" }
    return $d
}

function Move-ToQuarantine([string]$Path, [string]$Reason = '') {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
    New-PrivateDir $Script:QDir | Out-Null
    $item = Get-Item -LiteralPath $Path -Force
    $safe = (Limit-Text ([regex]::Replace($item.Name, '[^A-Za-z0-9._-]+', '_')) 60).Replace('..', '_')
    $stem = (Get-Date -Format 'yyyyMMdd-HHmmss') + '_' + $safe
    $qid = $stem; $n = 1
    while (Test-Path -LiteralPath (Join-Path $Script:QDir $qid)) { $n++; $qid = "${stem}_$n" }
    $target = New-PrivateDir (Join-Path $Script:QDir $qid)
    $hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLower()
    $dst = Join-Path $target ($item.Name + '.quarantined')
    Move-Item -LiteralPath $item.FullName -Destination $dst -Force
    if (-not $Script:IsWin) { try { & chmod 400 $dst 2>$null } catch { Write-Verbose 'chmod failed' } }
    $meta = [ordered]@{ id = $qid; original = $item.FullName; sha256 = $hash; reason = $Reason; time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') }
    Save-TextUtf8 (Join-Path $target 'info.json') ($meta | ConvertTo-Json)
    return $qid
}

function Restore-FromQuarantine([string]$Id) {
    $d = Get-QuarantineDir $Id
    $meta = (Get-Content -LiteralPath (Join-Path $d 'info.json') -Raw) | ConvertFrom-Json
    $src = Get-ChildItem -LiteralPath $d -Filter '*.quarantined' | Select-Object -First 1
    if (Test-Path -LiteralPath $meta.original) { throw "A file already exists at the original location: $($meta.original)" }
    New-Item -ItemType Directory -Force -Path (Split-Path $meta.original -Parent) | Out-Null
    Move-Item -LiteralPath $src.FullName -Destination $meta.original
    if (-not $Script:IsWin) { try { & chmod 600 $meta.original 2>$null } catch { Write-Verbose 'chmod failed' } }
    Remove-Item -LiteralPath $d -Recurse -Force
    return $meta.original
}

function Remove-FromQuarantine([string]$Id) {
    $d = Get-QuarantineDir $Id
    Remove-Item -LiteralPath $d -Recurse -Force
}

function Show-Quarantine {
    if (-not (Test-Path -LiteralPath $Script:QDir)) { Write-Line 'The quarantine is empty.'; return }
    $n = 0
    foreach ($d in Get-ChildItem -LiteralPath $Script:QDir -Directory) {
        $info = Join-Path $d.FullName 'info.json'
        if (-not (Test-Path -LiteralPath $info)) { continue }
        $m = (Get-Content -LiteralPath $info -Raw) | ConvertFrom-Json
        Write-Line $m.id 'White'; Write-Line ('    ' + $m.original); Write-Line ('    ' + $m.reason) 'DarkGray'
        $n++
    }
    if ($n -eq 0) { Write-Line 'The quarantine is empty.' }
}

# ------------------------------------------------------------------ reports
function Get-Counts {
    $c = [ordered]@{ 'DETECTED' = 0; 'WARNING' = 0; 'NOT CHECKED' = 0; 'INFO' = 0; 'OK' = 0 }
    foreach ($f in $Script:Findings) { $c[$f.sev]++ }
    return $c
}

function ConvertTo-HtmlText([string]$s) { return [System.Net.WebUtility]::HtmlEncode($s) }

function Save-HtmlReport([string]$Path, $Meta) {
    $c = Get-Counts
    $colors = @{ 'DETECTED' = '#C00000'; 'WARNING' = '#806000'; 'NOT CHECKED' = '#404040'; 'INFO' = '#000080'; 'OK' = '#006000' }
    $order = @{ 'DETECTED' = 0; 'WARNING' = 1; 'NOT CHECKED' = 2; 'INFO' = 3; 'OK' = 4 }
    $rows = ($Script:Findings | Sort-Object { $order[$_.sev] } | ForEach-Object {
            $src = ''; if ($_.source) { $src = "<div class='src'>Source: $(ConvertTo-HtmlText $_.source)</div>" }
            "<tr><td style='color:$($colors[$_.sev]);font-weight:bold'>$(ConvertTo-HtmlText $_.sev)</td><td>$(ConvertTo-HtmlText $_.area)</td><td><b>$(ConvertTo-HtmlText $_.title)</b><pre>$(ConvertTo-HtmlText $_.detail)</pre>$src</td></tr>"
        }) -join ''
    $metaRows = ($Meta.GetEnumerator() | ForEach-Object { "<tr><td>$(ConvertTo-HtmlText $_.Key)</td><td>$(ConvertTo-HtmlText ([string]$_.Value))</td></tr>" }) -join ''
    $css = 'body{background:#008080;margin:0;padding:24px;font:13px Tahoma,"MS Sans Serif",Arial,sans-serif;color:#000}.win{background:#C0C0C0;border:2px solid;border-color:#FFF #404040 #404040 #FFF;max-width:1100px;margin:auto}.bar{background:#000080;color:#FFF;font-weight:bold;padding:4px 8px}.in{padding:12px}table{border-collapse:collapse;width:100%;background:#FFF;border:2px solid;border-color:#808080 #FFF #FFF #808080}td,th{border:1px solid #C0C0C0;padding:4px 6px;vertical-align:top;text-align:left}th{background:#C0C0C0}pre{margin:4px 0 0;font:12px "Courier New",monospace;white-space:pre-wrap;word-break:break-all}.src{font-size:11px;color:#404040}.sum span{display:inline-block;margin-right:18px;font-weight:bold}.note{border:2px solid;border-color:#808080 #FFF #FFF #808080;background:#FFFFE1;padding:8px;margin:10px 0}'
    $note = 'A result without detections is no guarantee. High-end spyware is built to survive checks like this, and many traces disappear within a few weeks. If you have a well-founded suspicion, contact the Access Now Digital Security Helpline or the Amnesty International Security Lab.'
    $guide = 'https://github.com/SedicCodeStudio/scs-scanner/blob/main/docs/WHAT-TO-DO.md'
    $html = "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>SCS Scanner Report</title><style>$css</style></head><body><div class='win'><div class='bar'>SCS Scanner - Scan report (PowerShell edition)</div><div class='in'>" +
    "<p class='sum'><span style='color:#C00000'>Detected: $($c['DETECTED'])</span><span style='color:#806000'>Warnings: $($c['WARNING'])</span><span>Not checked: $($c['NOT CHECKED'])</span><span style='color:#000080'>Info: $($c['INFO'])</span><span style='color:#006000'>OK: $($c['OK'])</span></p>" +
    "<div class='note'>$note <a href='$guide'>What to do if something was found</a></div><table><tr><th colspan='2'>Scan</th></tr>$metaRows</table><br><table><tr><th style='width:110px'>Status</th><th style='width:150px'>Area</th><th>Finding</th></tr>$rows</table></div></div></body></html>"
    Save-TextUtf8 $Path $html
}

function Save-JsonReport([string]$Path, $Meta) {
    $doc = [ordered]@{ meta = $Meta; counts = (Get-Counts); findings = $Script:Findings.ToArray() }
    Save-TextUtf8 $Path ($doc | ConvertTo-Json -Depth 5)
}

# ------------------------------------------------------------------ main
function Show-Banner {
    Write-Line '+--------------------------------------------------------------+' 'DarkGray'
    if ($NoColor) { Write-Host ('|  >_SCS   SCS Scanner ' + $Script:AppVersion + ' - PowerShell edition') }
    else { Write-Host '|  ' -NoNewline -ForegroundColor DarkGray; Write-Host '>_SCS' -NoNewline -ForegroundColor Green -BackgroundColor Black; Write-Host ("   SCS Scanner $($Script:AppVersion) - PowerShell edition") -ForegroundColor White }
    Write-Line '|  Sedic Code Studio - spyware, malware, hidden files, traffic   ' 'DarkGray'
    Write-Line '+--------------------------------------------------------------+' 'DarkGray'
}

function Invoke-Scan {
    $admin = Test-Admin
    $meta = [ordered]@{ program = "SCS Scanner $($Script:AppVersion) (PowerShell)"; system = [string][Environment]::OSVersion.VersionString; host = [Environment]::MachineName; started = $Script:Started.ToString('yyyy-MM-dd HH:mm:ss'); mode = "$Mode scan"; admin_root = $admin }
    # indicators
    $metaFile = Join-Path $Script:IocDir 'feeds.json'
    $stale = $true
    if (Test-Path -LiteralPath $metaFile) { $stale = ((Get-Date) - (Get-Item -LiteralPath $metaFile).LastWriteTime).TotalDays -gt 7 }
    if ($Update -or ($stale -and -not $NoUpdate)) {
        try { Update-Indicators } catch { Write-Line ('Indicator update failed: ' + $_.Exception.Message + ' - continuing with the lists already present.') 'Yellow' }
    }
    Write-Step 'Loading indicators'
    Import-Indicators
    Test-IocStatus
    if (-not $admin) {
        $tip = 'Run PowerShell as administrator for the full check.'; if (-not $Script:IsWin) { $tip = 'For the full check: sudo pwsh ./scs.ps1' }
        Add-Finding 'INFO' 'Permissions' 'Started without admin/root rights' ("Some areas (system services, other users' processes, Defender exclusions) remain limited. " + $tip)
    }
    if ($Script:IsWin) {
        Write-Step 'Autostart'; Invoke-Check 'Autostart' { Test-Autostart }
        Write-Step 'Scheduled tasks'; Invoke-Check 'Scheduled tasks' { Test-Tasks }
        Write-Step 'Services'; Invoke-Check 'Services' { Test-Services }
    }
    else { Add-Finding 'NOT CHECKED' 'Autostart' 'Autostart, services and tasks are checked by the Python version on this system' 'Run: python3 scs.pyz scan' }
    Write-Step 'Processes'; Invoke-Check 'Processes' { Test-Processes }
    if ($Script:IsWin) {
        if ($Mode -eq 'Full') { Write-Step 'Signatures'; Invoke-Check 'Signatures' { Test-Signatures } }
        Write-Step 'VPN, proxy, DNS servers, certificates'; Invoke-Check 'VPN' { Test-Routing }
        Write-Step 'DNS history'; Invoke-Check 'DNS' { Test-DnsHistory }
        Invoke-Check 'Network' { Test-Connections }
        Write-Step 'Defender'; Invoke-Check 'Defender' { Test-Defender }
        Invoke-Check 'Recycle Bin' { Test-RecycleBin }
    }
    Invoke-Check 'Network' { Test-Hosts }
    Write-Step 'Known spyware file paths'; Invoke-Check 'Traces' { Test-IocPaths }
    Write-Step 'Browser histories'; Invoke-Check 'Browser' { Test-Browsers }
    Write-Step 'File fingerprints'; Invoke-Check 'Files' { Test-Hashes }
    Write-Step 'Hidden images & caches'
    Invoke-Check 'Thumbnail caches' { Test-ThumbCache }
    Invoke-Check 'Hidden images' { Test-HiddenImages }
    if ($Script:IsWin -and $Mode -eq 'Full') { Write-Step 'Hidden data streams'; Invoke-Check 'Hidden data streams' { Test-Ads } }
    Invoke-Check 'Changes' { Compare-Baseline }
    $c = Get-Counts
    $sev = 'INFO'; if (-not ($c['DETECTED'] -or $c['WARNING'])) { $sev = 'OK' }
    Add-Finding $sev 'Result' ("$($c['DETECTED']) detected, $(Get-CountText $c['WARNING'] 'warning'), $($c['NOT CHECKED']) not checked") 'A result without detections is no guarantee: high-end spyware is built to survive checks like this, and many traces disappear within a few weeks.'
    $meta['vpn'] = $(if ($Script:Vpn.Count) { $Script:Vpn -join ', ' } else { 'none active' })
    return $meta
}

function Start-Scs {
    if ($Version) { Write-Host "SCS Scanner $($Script:AppVersion) (PowerShell edition)"; return 0 }
    Show-Banner
    New-PrivateDir $Script:DataDir | Out-Null
    if ($ListQuarantine) { Show-Quarantine; return 0 }
    if ($Restore) { Write-Line ('Restored: ' + (Restore-FromQuarantine $Restore)) 'Green'; return 0 }
    if ($DeleteQuarantine) { Remove-FromQuarantine $DeleteQuarantine; Write-Line "Deleted from quarantine: $DeleteQuarantine" 'Green'; return 0 }
    if ($Quarantine) { Write-Line ('Moved to quarantine: ' + (Move-ToQuarantine $Quarantine 'moved by the user')) 'Green'; return 0 }
    if ($SelfTest) {
        $dir = New-PrivateDir (Join-Path $Script:DataDir 'selftest')
        $file = Join-Path $dir 'SCS-SELFTEST.txt'
        [IO.File]::WriteAllBytes($file, [Text.Encoding]::ASCII.GetBytes($Script:SelfTestText))
        Import-Indicators
        $h = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
        if ($Script:IOC.sha256.ContainsKey($h)) {
            Add-Finding 'DETECTED' 'Self-test' 'Test file detected' $file -Source 'SCS self-test (harmless)'
            $qid = Move-ToQuarantine $file 'Self-test'
            Write-Line "`nSelf-test passed: the test file was detected and moved to quarantine ($qid)." 'Green'
            return 0
        }
        Write-Line "`nSelf-test FAILED: the test file was not detected." 'Red'
        return 2
    }
    $meta = Invoke-Scan
    New-PrivateDir $Script:ReportDir | Out-Null
    if (-not $Report) { $Report = Join-Path $Script:ReportDir ('SCS-Report-' + (Get-Date -Format 'yyyyMMdd-HHmm') + '.html') }
    Save-HtmlReport $Report $meta
    Write-Line "`nReport: $Report" 'White'
    if ($Json) { Save-JsonReport $Json $meta; Write-Line "Data:   $Json" 'White' }
    if ($Open) { try { Invoke-Item -LiteralPath $Report } catch { Write-Line 'The report could not be opened automatically.' 'Yellow' } }
    if ((Get-Counts)['DETECTED']) { return 1 }
    return 0
}

if ($env:SCS_PS_NO_MAIN -eq '1') { return }   # used by the test suite
$code = Start-Scs
# "exit" would close the PowerShell window when the script runs as a one-line command
if ($Script:RunAsFile) { exit $code }
