@echo off
SETLOCAL EnableDelayedExpansion

echo ============================================================
echo           SAERA - PostgreSQL Production Setup Utility
echo ============================================================
echo.
echo This script will help you initialize your PostgreSQL database.
echo Make sure PostgreSQL is installed and the 'bin' folder is in your PATH.
echo.

set /p PGUSER_SUPER="Enter PostgreSQL Superuser (default: postgres): "
if "!PGUSER_SUPER!"=="" set PGUSER_SUPER=postgres

echo.
echo Step 1: Creating Database and User...
echo Please enter the password for the PostgreSQL superuser (%PGUSER_SUPER%) when prompted.
echo.

set /p DBNAME="Enter new Database Name (default: saera_db): "
if "!DBNAME!"=="" set DBNAME=saera_db

set /p DBUSER="Enter new Database User (default: saera_user): "
if "!DBUSER!"=="" set DBUSER=saera_user

set /p DBPASS="Enter password for !DBUSER!: "

:: Create SQL script
echo CREATE DATABASE !DBNAME!; > pg_setup.sql
echo CREATE USER !DBUSER! WITH PASSWORD '!DBPASS!'; >> pg_setup.sql
echo GRANT ALL PRIVILEGES ON DATABASE !DBNAME! TO !DBUSER!; >> pg_setup.sql

:: Execute SQL script
psql -U %PGUSER_SUPER% -h localhost -f pg_setup.sql
del pg_setup.sql

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Failed to create database. Please check your credentials or if Postgres is running.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Step 2: Updating .env file...
if not exist .env (
    echo [INFO] .env not found. Creating from .env.example...
    copy .env.example .env
)

:: Use powershell to update .env values
powershell -Command "(GC .env) -replace 'DB_NAME=.*', 'DB_NAME=!DBNAME!' | Out-File -encoding ASCII .env"
powershell -Command "(GC .env) -replace 'DB_USER=.*', 'DB_USER=!DBUSER!' | Out-File -encoding ASCII .env"
powershell -Command "(GC .env) -replace 'DB_PASSWORD=.*', 'DB_PASSWORD=!DBPASS!' | Out-File -encoding ASCII .env"
powershell -Command "(GC .env) -replace 'DB_HOST=.*', 'DB_HOST=localhost' | Out-File -encoding ASCII .env"
powershell -Command "(GC .env) -replace 'DB_PORT=.*', 'DB_PORT=5432' | Out-File -encoding ASCII .env"

echo [SUCCESS] .env updated with PostgreSQL credentials.

echo.
echo Step 3: Running Django Migrations...
call venv\Scripts\activate
python manage.py migrate

echo.
echo ============================================================
echo [COMPLETE] PostgreSQL Setup Finished!
echo Your SAERA Engine is now running on the Production Kernel.
echo ============================================================
pause
