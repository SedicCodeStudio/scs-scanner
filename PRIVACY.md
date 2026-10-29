# Privacy

**In short:** the SCS Scanner works on your own device. It has no account, no telemetry, no advertising and no cloud
analysis. Scan results stay on your computer unless you decide to share a report.

## What the program reads

To find spyware and malware, the scanner reads – on the device you start it on, or on the phone you connect – lists of
programs, autostart entries, services, network settings, browser histories, file names and fingerprints of files in
typical malware locations, and (for phones) app lists and system information. This is compared with public indicator
lists **locally**. Nothing of this is sent anywhere.

## What is stored on your device

All in the folder `.scs-scanner` in your user folder (private to your user account):

| Folder | Content | Removal |
|---|---|---|
| `indicators/` | the downloaded public indicator lists | delete freely |
| `baseline/` | the state of the last scan per device, for the change detection | delete to start over |
| `quarantine/` | files you moved to quarantine | "Show quarantine" › Delete |
| `reports/` | reports of the PowerShell edition | delete freely |
| `logs/scs.log` | which checks ran and program errors – **no findings, file contents or matches** | delete freely |
| `yara/` | optional YARA rules | delete freely |

Uninstalling the program keeps this folder on purpose (reports and quarantine can be evidence). Delete it yourself if
you no longer need it.

## Network requests

Only these, and only when you start the corresponding function:

- **Update indicators** – downloads the public lists from GitHub (`raw.githubusercontent.com`, `github.com`).
- **YARA rules** (`scs update --yara`) – downloads the signature-base rules from GitHub.
- **Update check** (`scs update`, `scs version --check`, "Check for updates") – one request to `github.com` that reads
  the number of the newest release.
- The PowerShell one-line command downloads the script itself from GitHub.

Like every web request, these show your IP address to GitHub (GitHub, Inc., USA). No scan data, device data or
identifiers are sent. When the scanner checks an Android phone or an iPhone, it only talks to that device (USB or SSH).

## Reports

HTML and JSON reports contain the findings and can contain file paths, app names, network settings and user names.
Treat them as private. Only send a report to people you trust (for example a security lab that helps you).

## Contact

Sedic Code Studio – info@sediccodestudio.de
