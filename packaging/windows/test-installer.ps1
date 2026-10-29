<#
    Tests SCS-Scanner-Setup-<version>.exe: silent install into a temporary folder, installed files and version
    information, self-test of the installed "SCS Scanner.exe", its window opens, the installed PowerShell edition runs,
    silent uninstall. Used by CI and by the release workflow (a broken installer is never published); also works on any
    Windows PC after build.ps1:
        powershell -ExecutionPolicy Bypass -File packaging\windows\test-installer.ps1 [-Setup PATH]
#>
param([string]$Setup)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$version = (Select-String -Path (Join-Path $root 'scs\core.py') -Pattern '^VERSION = "(.+)"').Matches[0].Groups[1].Value
if (-not $Setup) { $Setup = Join-Path $root "dist\SCS-Scanner-Setup-$version.exe" }
$setupFile = Get-Item -LiteralPath $Setup
$tmp = [IO.Path]::GetTempPath()
$dir = Join-Path $tmp ('SCS Scanner test ' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$exePath = Join-Path $dir 'SCS Scanner.exe'

function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }

$p = Start-Process -FilePath $setupFile.FullName -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$dir`"" -Wait -PassThru
Assert-True ($p.ExitCode -eq 0) "setup ended with exit code $($p.ExitCode)"
Write-Host "Installed $($setupFile.Name) ($([math]::Round($setupFile.Length / 1MB, 1)) MB) to $dir"
try {
    foreach ($f in 'SCS Scanner.exe', 'unins000.exe', 'powershell\scs.ps1', 'LICENSE', 'NOTICE.txt', 'README.md', 'WHAT-TO-DO.md') {
        Assert-True (Test-Path -LiteralPath (Join-Path $dir $f)) "missing after install: $f"
    }
    $exe = Get-Item -LiteralPath $exePath
    Assert-True ($exe.VersionInfo.ProductVersion -eq $version) "wrong version information: $($exe.VersionInfo.ProductVersion)"
    Write-Host "  files and version information ($version): OK"

    # self-test of the installed program, without a window
    $report = Join-Path $tmp 'scs-installed-check.txt'
    Remove-Item -LiteralPath $report -ErrorAction SilentlyContinue
    $p = Start-Process -FilePath $exe.FullName -ArgumentList '--check', "`"$report`"" -Wait -PassThru
    if (Test-Path -LiteralPath $report) { Get-Content -LiteralPath $report | Where-Object { $_ } | Select-Object -Last 2 | ForEach-Object { Write-Host "  $_" } }
    Assert-True ($p.ExitCode -eq 0) "self-test of the installed program failed (exit code $($p.ExitCode))"

    # the window opens (the first-start notice is skipped for this test only)
    $consent = Join-Path $env:USERPROFILE '.scs-scanner\consent.txt'
    $madeConsent = -not (Test-Path -LiteralPath $consent)
    if ($madeConsent) {
        New-Item -ItemType Directory -Force -Path (Split-Path $consent) | Out-Null
        Set-Content -LiteralPath $consent -Value 'installer test' -Encoding Ascii
    }
    try {
        $gui = Start-Process -FilePath $exe.FullName -PassThru
        $title = ''
        for ($i = 0; $i -lt 60 -and -not $title -and -not $gui.HasExited; $i++) {
            Start-Sleep -Milliseconds 500
            $gui.Refresh()
            $title = $gui.MainWindowTitle
        }
        $ended = $gui.HasExited
        if (-not $ended) { Stop-Process -Id $gui.Id -Force; $null = $gui.WaitForExit(15000) }
    }
    finally {
        if ($madeConsent) { Remove-Item -LiteralPath $consent -Force -ErrorAction SilentlyContinue }
    }
    Assert-True (-not $ended) "the program ended right after starting (exit code $($gui.ExitCode))"
    if ($title) {
        Assert-True ($title -like "SCS Scanner $version*") "unexpected window instead of the program: '$title'"
        Write-Host "  window opened: $title"
    }
    else {
        Write-Warning 'no window title visible (no desktop session?) - the program ran for 30 seconds without ending'
    }

    # the installed PowerShell edition
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dir 'powershell\scs.ps1') -Version
    Assert-True ("$out" -match [regex]::Escape($version)) "installed PowerShell edition reports: $out"
    Write-Host "  PowerShell edition: $out"
}
finally {
    $uninstaller = Join-Path $dir 'unins000.exe'
    if (Test-Path -LiteralPath $uninstaller) {
        $u = Start-Process -FilePath $uninstaller -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
        for ($i = 0; $i -lt 60 -and (Test-Path -LiteralPath $exePath); $i++) { Start-Sleep -Seconds 1 }
        if ($u.ExitCode) { Write-Warning "uninstall ended with exit code $($u.ExitCode)" }
    }
}
Assert-True (-not (Test-Path -LiteralPath $exePath)) 'the program is still there after uninstalling'
Write-Host '  uninstall: OK'
Write-Host "Installer test passed: $($setupFile.Name)"
