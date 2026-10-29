# One-line commands

Copy one line into PowerShell or a terminal and press Enter. Only check your own devices, or devices whose owner agreed.
The release page of every version contains this list with the checksums of that version already filled in.

## Windows – PowerShell, nothing to install

Open **PowerShell** (Start menu → type “PowerShell”). For the full check choose **“Run as administrator”**.

Quick scan – the report opens in the browser when the scan is done:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/SedicCodeStudio/scs-scanner/main/powershell/scs.ps1))) -Open
```

Full scan (signatures, hidden data streams, appended data in images):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/SedicCodeStudio/scs-scanner/main/powershell/scs.ps1))) -Mode Full -Open
```

Verified – downloads the release file, compares its SHA-256 checksum with the one published in the release
(`SHA256SUMS`, replace `CHECKSUM`) and only then starts it:

```powershell
$f="$env:TEMP\scs.ps1"; iwr https://github.com/SedicCodeStudio/scs-scanner/releases/latest/download/scs.ps1 -OutFile $f -UseBasicParsing; if ((Get-FileHash $f -Algorithm SHA256).Hash -eq 'CHECKSUM') { powershell -NoProfile -ExecutionPolicy Bypass -File $f -Open } else { Write-Warning 'Checksum mismatch - the file was not started.' }
```

More options of the PowerShell edition:

| Option | Effect |
|---|---|
| `-Mode Full` | thorough scan, takes longer |
| `-Open` | open the HTML report when done |
| `-Json C:\path\scan.json` | also save a JSON report (combine several devices with `scs merge`) |
| `-Update` / `-NoUpdate` | download the indicator lists now / never (offline) |
| `-SelfTest` | harmless test that detection and quarantine work |
| `-ListQuarantine`, `-Quarantine FILE`, `-Restore ID`, `-DeleteQuarantine ID` | manage the quarantine |
| `-NoBaseline` | do not compare with the last scan |
| `-Version` | show the version |

## Linux and macOS – terminal

Python 3 is preinstalled on most Linux systems; on a Mac run `xcode-select --install` once if `python3` is missing.

Quick scan with a verified download (replace `CHECKSUM` with the value from `SHA256SUMS` of the release):

```sh
curl -fsSLO https://github.com/SedicCodeStudio/scs-scanner/releases/latest/download/scs.pyz && echo "CHECKSUM  scs.pyz" | shasum -a 256 -c - && python3 scs.pyz scan --html scs-report.html
```

Full scan with root rights:

```sh
sudo python3 scs.pyz scan --full --html scs-report.html
```

Phones:

```sh
python3 scs.pyz android                       # Android over USB (needs adb and USB debugging)
python3 scs.pyz iphone-backup ~/path/to/backup  # iPhone backup made with Finder or iTunes
```

With PowerShell 7 installed, the PowerShell edition also runs on Linux and macOS (fewer checks than the Python version):

```sh
pwsh -c '& ([scriptblock]::Create((irm https://raw.githubusercontent.com/SedicCodeStudio/scs-scanner/main/powershell/scs.ps1))) -Open'
```

## Why `[scriptblock]::Create(...)` and not `irm | iex`?

Both download the script and run it in memory. The script-block form runs it in its own scope, so it does not change the
settings of your PowerShell window, and it accepts options such as `-Mode Full`. Nothing is installed and nothing stays
behind except the indicator lists, the quarantine and the reports in `%USERPROFILE%\.scs-scanner`.
