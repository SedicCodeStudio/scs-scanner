@echo off
rem PowerShell edition of the SCS Scanner - needs no Python. For the full check: right-click > Run as administrator.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0powershell\scs.ps1" -Open %*
pause
