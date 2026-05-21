@echo off
REM NetVuln - simple Windows setup script

echo NetVuln Setup
echo =============
echo.

py -3.11 --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python 3.11 is not installed.
    echo Install it from https://www.python.org/downloads/
    pause
    exit /b 1
)

nmap --version >nul 2>&1
if errorlevel 1 (
    echo Note: nmap is not installed. The project can still run, but scan results may be limited.
) else (
    echo nmap is installed.
)
echo.

echo [1/6] Creating virtual environment...
py -3.11 -m venv venv
if errorlevel 1 (
    echo Error: Failed to create virtual environment.
    pause
    exit /b 1
)

set VENV_PY=venv\Scripts\python.exe
if not exist %VENV_PY% (
    echo Error: venv python not found.
    pause
    exit /b 1
)

echo [2/6] Upgrading pip...
%VENV_PY% -m pip install --upgrade pip setuptools wheel

echo [3/6] Installing dependencies...
%VENV_PY% -m pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

if not exist .env (
    echo [4/6] Creating .env file...
    copy .env.example .env >nul
) else (
    echo [4/6] .env already exists.
)

echo [5/6] Applying migrations...
%VENV_PY% manage.py migrate
if errorlevel 1 (
    echo Error: Failed to apply migrations.
    pause
    exit /b 1
)

echo [6/6] Creating media directories...
if not exist media mkdir media

echo.
echo Setup complete.
echo Run the app with:
echo   venv\Scripts\python.exe manage.py runserver 8000
echo.
if "%1"=="--no-pause" goto end
pause
:end
