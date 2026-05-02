@echo off
REM SAERA - Security Assessment & External Risk Analysis - Windows Setup Script

echo SAERA - Security Setup Console
echo ==================================
echo.

REM --- FORCE PYTHON 3.11 ---
py -3.11 --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python 3.11 is not installed.
    echo Install it from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check nmap (optional)
nmap --version >nul 2>&1
if errorlevel 1 (
    echo Note: nmap is not installed. The built-in socket scanner will be used.
    echo       Install nmap for richer results: https://nmap.org/download.html
    echo.
) else (
    echo nmap is installed - enhanced scanning available.
)

REM Check Redis
echo Checking for Redis...
set REDIS_RUNNING=0
redis-cli ping >nul 2>&1
if not errorlevel 1 set REDIS_RUNNING=1

if "%REDIS_RUNNING%"=="1" (
    echo Redis is running.
) else (
    echo Warning: Redis is not running or not installed.
    echo The app will run in synchronous mode.
    echo.
)

REM Create virtual environment (FORCED PYTHON 3.11)
echo [1/8] Creating virtual environment...
py -3.11 -m venv venv
if errorlevel 1 (
    echo Error: Failed to create virtual environment.
    pause
    exit /b 1
)

REM Define venv python (CRITICAL FIX)
set VENV_PY=venv\Scripts\python.exe

if not exist %VENV_PY% (
    echo Error: venv python not found.
    pause
    exit /b 1
)

REM Check version (debug)
echo [2/8] Checking Python version...
%VENV_PY% --version

REM Upgrade pip
echo [3/8] Upgrading pip...
%VENV_PY% -m pip install --upgrade pip setuptools wheel

REM Install dependencies
echo [4/8] Installing Python dependencies...
%VENV_PY% -m pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

REM Copy .env
if not exist .env (
    echo [5/8] Creating .env file from template...
    copy .env.example .env
    echo Please edit the .env file and set your SECRET_KEY.
) else (
    echo [5/8] .env file already exists, skipping...
)

REM Handle Redis flag
if "%REDIS_RUNNING%"=="0" (
    findstr /i "CELERY_TASK_ALWAYS_EAGER" .env >nul 2>&1
    if errorlevel 1 (
        echo CELERY_TASK_ALWAYS_EAGER=True>>.env
    ) else (
        powershell -Command "(Get-Content .env) -replace 'CELERY_TASK_ALWAYS_EAGER=.*','CELERY_TASK_ALWAYS_EAGER=True' | Set-Content .env"
    )
)

REM Make migrations (CRITICAL FIX)
echo [6/8] Creating database migrations...
%VENV_PY% manage.py makemigrations
if errorlevel 1 (
    echo Error: Failed to create migrations.
    pause
    exit /b 1
)

REM Apply migrations
echo [7/8] Applying database migrations...
%VENV_PY% manage.py migrate
if errorlevel 1 (
    echo Error: Failed to apply migrations.
    pause
    exit /b 1
)

REM Create media directories
echo [8/8] Creating media directories...
if not exist media\reports mkdir media\reports

echo.
echo ==================================
echo Setup Complete!
echo ==================================
echo.
echo Run server:
echo venv\Scripts\python.exe manage.py runserver
echo.
pause