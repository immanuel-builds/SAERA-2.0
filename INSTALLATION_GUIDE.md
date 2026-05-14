# SAERA - Installation & Prerequisites Guide

This guide provides a step-by-step walkthrough for setting up the SAERA (Security Assessment & External Risk Analysis) environment across Windows, macOS, and Linux.

---

## 📋 System Requirements

### Functional Requirements (Software)
- **Core Runtime**: Python 3.11 or higher
- **Scanning Engine**: Nmap 7.90+ (Optional but highly recommended)
- **Task Broker**: Redis 6.0+ (Required for asynchronous scanning)
- **Database Engine**: PostgreSQL 14+ (Production) or SQLite (Development)
- **Package Manager**: Pip 23.0+

### Non-Functional Requirements (Hardware)
- **RAM**: Minimum 4GB (8GB recommended for concurrent scanning)
- **Storage**: 500MB free space (for logs and reports)
- **Network**: Broadband connection (for external scanning)

---

## 🔍 Pre-Installation Check
Before installing anything, run these commands in your terminal to see what you already have. You can skip the installation steps for any tool that returns a valid version.

| Component | Command to Check | Expected Response |
| :--- | :--- | :--- |
| **Python** | `python --version` or `py --version` | `Python 3.11.x` |
| **Nmap** | `nmap --version` | `Nmap version 7.xx` |
| **Redis** | `redis-cli ping` | `PONG` |
| **PostgreSQL** | `psql --version` | `psql (PostgreSQL) 1x.x` |
| **Docker** | `docker --version` | `Docker version 2x.x` |

---

## 🛠️ Installation Phase

### 1. Python 3.11+
- **Windows**: Download the installer from [python.org](https://www.python.org/downloads/windows/). **CRITICAL**: Check the box "Add Python to PATH" during installation.
- **macOS**: `brew install python@3.11`
- **Linux (Ubuntu/Debian)**: `sudo apt update && sudo apt install python3.11 python3.11-venv`

### 2. Nmap (The Scanner Limb)
- **Windows**: Download the "Self-installer" from [nmap.org](https://nmap.org/download.html).
- **macOS**: `brew install nmap`
- **Linux**: `sudo apt install nmap`

### 3. Redis (The Task Broker)
- **Windows (Recommended)**: Use **Docker Desktop** to run Redis:
  ```bash
  docker run --name redis -p 6379:6379 -d redis
  ```
- **macOS**: `brew install redis` then `brew services start redis`
- **Linux**: `sudo apt install redis-server` then `sudo systemctl start redis`

### 4. PostgreSQL (The Data Kernel)
- **Windows**: Download the "Interactive Installer" from [EnterpriseDB](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads).
- **macOS**: `brew install postgresql` then `brew services start postgresql`
- **Linux**: `sudo apt install postgresql postgresql-contrib`

---

## 🚀 Project Setup (Step-by-Step)

### Step 1: Clone the Repository
```bash
git clone https://github.com/immanuel-builds/saera.git
cd saera
```

### Step 2: Virtual Environment
```bash
# Windows
py -3.11 -m venv venv
venv\Scripts\activate

# macOS/Linux
python3.11 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Environment Configuration
1. Copy `.env.example` to `.env`.
2. Generate a `SECRET_KEY` and paste it into `.env`.
3. (Optional) Enter your PostgreSQL credentials to enable the production kernel.

### Step 5: Database Initialization
```bash
python manage.py makemigrations
python manage.py migrate
```

### Step 6: Create Superuser (Admin)
```bash
python manage.py createsuperuser
```

---

## ✅ Post-Installation Verification
To ensure everything is working correctly, run the automated setup script:

- **Windows**: Run `setup.bat`
- **macOS/Linux**: Run `python manage.py check`

If the **Engine Core** dashboard shows "Healthy" for all services (Web Server, Database, Redis), your installation is successful!
