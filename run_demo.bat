@echo off
rem Double-click this file to run the demo on Windows.
rem It opens in this folder, runs the full demo, and keeps the window open.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (py main.py demo) else (python main.py demo)
echo.
echo ---- demo finished. press any key to close ----
pause >nul
