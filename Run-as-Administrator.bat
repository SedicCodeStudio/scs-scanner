@echo off
powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~dp0Start-Windows.bat' -WorkingDirectory '%~dp0'"
