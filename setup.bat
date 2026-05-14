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

REM --- DOCKER & REDIS STARTUP ---
echo Checking for Redis (Docker)...

set REDIS_RUNNING=0
set DOCKER_DESKTOP="C:\Program Files\Docker\Docker\Docker Desktop.exe"
set REDIS_CONTAINER=redis

REM 1. Check if Docker is running
docker info >nul 2>&1
if not errorlevel 1 goto docker_running

echo Docker is not running. Attempting to start Docker Desktop...
if not exist %DOCKER_DESKTOP% (
    echo Error: Docker Desktop not found at %DOCKER_DESKTOP%.
    echo Please start Docker Desktop manually.
    goto docker_done
)

start "" %DOCKER_DESKTOP%
echo Waiting for Docker to start (this may take a minute)...

set wait_count=0
:wait_docker
set /a wait_count+=1
if %wait_count% gtr 12 (
    echo Error: Docker Desktop took too long to start. 
    echo Continuing setup in synchronous mode...
    goto docker_done
)
ping 127.0.0.1 -n 6 >nul
docker info >nul 2>&1
if errorlevel 1 (
    echo Still waiting for Docker ^(%wait_count%/12^)...
    goto wait_docker
)
echo Docker started successfully.

:docker_running
:docker_done

REM 2. Start Redis Container if Docker is available
docker info >nul 2>&1
if errorlevel 1 goto redis_done

echo Checking for Redis container...
docker ps -a --format "{{.Names}}" | findstr /i "^%REDIS_CONTAINER%$" >nul 2>&1
if errorlevel 1 (
    echo Warning: Redis container "%REDIS_CONTAINER%" not found.
    echo If your container has a different name, please edit setup.bat or create it manually.
    goto redis_done
)

docker ps --format "{{.Names}}" | findstr /i "^%REDIS_CONTAINER%$" >nul 2>&1
if errorlevel 1 (
    echo Starting Redis container...
    docker start %REDIS_CONTAINER%
    ping 127.0.0.1 -n 3 >nul
) else (
    echo Redis container is already running.
)

REM Final check via CLI
redis-cli ping >nul 2>&1
if not errorlevel 1 (
    set REDIS_RUNNING=1
    goto redis_done
)

docker exec %REDIS_CONTAINER% redis-cli ping >nul 2>&1
if not errorlevel 1 set REDIS_RUNNING=1

:redis_done

if "%REDIS_RUNNING%"=="1" (
    echo Redis is ready and running.
) else (
    echo Warning: Redis could not be started or verified.
    echo The app will run in synchronous mode ^(CELERY_TASK_ALWAYS_EAGER=True^).
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
if "%REDIS_RUNNING%"=="1" goto env_done

findstr /i "CELERY_TASK_ALWAYS_EAGER" .env >nul 2>&1
if errorlevel 1 (
    echo CELERY_TASK_ALWAYS_EAGER=True>>.env
    goto env_done
)

powershell -Command "(Get-Content .env) -replace 'CELERY_TASK_ALWAYS_EAGER=.*','CELERY_TASK_ALWAYS_EAGER=True' | Set-Content .env"

:env_done

REM --- DATABASE INITIALIZATION ---
echo Checking database configuration...
%VENV_PY% -c "from django.conf import settings; print(settings.DATABASES['default']['ENGINE'])" | findstr /i "postgresql" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Running on SQLite fallback ^(local file database^).
) else (
    echo [INFO] Running on PostgreSQL production kernel.
    echo [INFO] Verifying PostgreSQL connectivity...
    %VENV_PY% manage.py check >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] PostgreSQL connection failed. Check your .env credentials.
        echo [INFO] Defaulting to SQLite for now...
    ) else (
        echo [OK] PostgreSQL connectivity verified.
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
echo.
echo ==================================
echo Setup Complete!
echo ==================================
echo.
echo Run server:
echo venv\Scripts\python.exe manage.py runserver 8000
echo.
if "%1"=="--no-pause" goto end
pause
:end