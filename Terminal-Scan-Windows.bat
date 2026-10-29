@echo off
chcp 65001 >nul
cd /d "%~dp0"
py -3 -c "import sys" >nul 2>nul && (py -3 scs.py scan --html SCS-Report.html & pause & exit /b)
python -c "import sys" >nul 2>nul && (python scs.py scan --html SCS-Report.html & pause & exit /b)
echo Python was not found - using the PowerShell edition (nothing to install).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0powershell\scs.ps1" -Report "%~dp0SCS-Report.html" -Open
pause
