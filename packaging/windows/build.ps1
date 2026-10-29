<#
    Builds "SCS Scanner.exe" (PyInstaller, one folder) and the installer SCS-Scanner-Setup-<version>.exe (Inno Setup).
    Needs Python 3.9+ with Tkinter and Inno Setup 6 or 7. Used by the release workflow; also works on any Windows PC:
        powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1
    Optional code signing: set SCS_SIGN_PFX (path to a .pfx file) and SCS_SIGN_PASSWORD before running.
#>
param([string]$Version)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Version) { $Version = (Select-String -Path (Join-Path $root 'scs\core.py') -Pattern '^VERSION = "(.+)"').Matches[0].Groups[1].Value }
$build = Join-Path $root 'build'
New-Item -ItemType Directory -Force -Path $build | Out-Null

python -m pip install --disable-pip-version-check --require-hashes -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE) { throw 'pip failed' }
python (Join-Path $PSScriptRoot 'make_version_file.py') $Version (Join-Path $build 'version_info.txt')
python -m PyInstaller --noconfirm --clean --windowed --name 'SCS Scanner' `
    --icon (Join-Path $PSScriptRoot 'scs.ico') --version-file (Join-Path $build 'version_info.txt') `
    --distpath (Join-Path $build 'pyinstaller') --workpath (Join-Path $build 'work') --specpath $build `
    --paths $root (Join-Path $PSScriptRoot 'launcher.py')
if ($LASTEXITCODE) { throw 'PyInstaller failed' }

function Sign-Files([string[]]$Files) {
    if (-not $env:SCS_SIGN_PFX) { return }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName | Select-Object -Last 1
    foreach ($f in $Files) {
        & $signtool.FullName sign /f $env:SCS_SIGN_PFX /p $env:SCS_SIGN_PASSWORD /fd sha256 /tr http://timestamp.digicert.com /td sha256 /d 'SCS Scanner' $f
        if ($LASTEXITCODE) { throw "signing failed: $f" }
    }
}
Sign-Files @(Join-Path $build 'pyinstaller\SCS Scanner\SCS Scanner.exe')

# Inno Setup 6 or 7: on the PATH, or in its default folder (the newest version wins)
$iscc = @(Get-Command ISCC.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
$iscc += @(Get-ChildItem "$env:ProgramFiles\Inno Setup *\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup *\ISCC.exe" -ErrorAction SilentlyContinue |
    Sort-Object { [int]($_.Directory.Name -replace '\D', '') } -Descending | ForEach-Object { $_.FullName })
$iscc = $iscc | Where-Object { $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup is not installed (https://jrsoftware.org/isdl.php or: choco install innosetup)' }
Write-Host "Using $iscc"
& $iscc "/DAppVersion=$Version" "/O$(Join-Path $root 'dist')" (Join-Path $PSScriptRoot 'installer.iss')
if ($LASTEXITCODE) { throw 'Inno Setup failed' }
$setup = Join-Path $root "dist\SCS-Scanner-Setup-$Version.exe"
Sign-Files @($setup)
Write-Host "Built $setup"
