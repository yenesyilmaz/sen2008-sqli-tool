@echo off
rem Double-click to open the interactive analyzer (type inputs live).
rem Commands inside: 'example' lists sample inputs, 'demo' runs all cases, 'exit' quits.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (py main.py) else (python main.py)
pause >nul
