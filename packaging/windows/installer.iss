; Installer of SCS Scanner (Inno Setup 6 or 7). Built by packaging\windows\build.ps1.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{8F6C2A44-5B1E-4C2A-9D7E-3A1F0B6C5D21}
AppName=SCS Scanner
AppVersion={#AppVersion}
AppVerName=SCS Scanner {#AppVersion}
AppPublisher=Sedic Code Studio
AppPublisherURL=https://github.com/SedicCodeStudio/scs-scanner
AppSupportURL=https://github.com/SedicCodeStudio/scs-scanner/issues
AppUpdatesURL=https://github.com/SedicCodeStudio/scs-scanner/releases
AppContact=info@sediccodestudio.de
DefaultDirName={autopf}\SCS Scanner
DefaultGroupName=SCS Scanner
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
OutputBaseFilename=SCS-Scanner-Setup-{#AppVersion}
SetupIconFile=scs.ico
UninstallDisplayIcon={app}\SCS Scanner.exe
UninstallDisplayName=SCS Scanner {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=classic
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={#AppVersion}
VersionInfoCompany=Sedic Code Studio
VersionInfoDescription=SCS Scanner Setup
VersionInfoCopyright=Copyright 2026 Sedic Code Studio
VersionInfoProductName=SCS Scanner
VersionInfoProductVersion={#AppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; Flags: unchecked

[Files]
Source: "..\..\build\pyinstaller\SCS Scanner\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\powershell\scs.ps1"; DestDir: "{app}\powershell"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\NOTICE"; DestDir: "{app}"; DestName: "NOTICE.txt"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\docs\WHAT-TO-DO.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SCS Scanner"; Filename: "{app}\SCS Scanner.exe"
Name: "{group}\SCS Scanner (terminal, PowerShell edition)"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -NoExit -File ""{app}\powershell\scs.ps1"" -Open"; WorkingDir: "{app}"
Name: "{group}\Uninstall SCS Scanner"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SCS Scanner"; Filename: "{app}\SCS Scanner.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\SCS Scanner.exe"; Description: "Start SCS Scanner"; Flags: nowait postinstall skipifsilent

[Messages]
FinishedLabel=Setup has installed SCS Scanner on your computer.%n%nYour reports, change history and quarantine are kept in %USERPROFILE%\.scs-scanner and are not removed when you uninstall the program.
