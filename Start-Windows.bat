@echo off
chcp 65001 >nul
cd /d "%~dp0"
where pyw >nul 2>nul && (start "" pyw -3 scs.py & exit /b)
where pythonw >nul 2>nul && (start "" pythonw scs.py & exit /b)
echo Python was not found - starting the PowerShell edition instead (nothing to install).
echo For the window version install Python from https://www.python.org/downloads/
echo and tick "Add python.exe to PATH".
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0powershell\scs.ps1" -Open
pause
