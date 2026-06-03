@echo off
rem Double-click to launch the web UI; it opens in your browser automatically.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (py main.py web) else (python main.py web)
pause >nul
