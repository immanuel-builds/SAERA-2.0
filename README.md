# SAERA - Security Assessment & External Risk Analysis

A comprehensive web-based security assessment platform built with Django for identifying, analyzing, and reporting network vulnerabilities with automated scanning tools.

## Features

- 🔍 **Port Scanning**: TCP/UDP port scanning using python-nmap
- 🛡️ **Service Enumeration**: Identify services and versions
- 🐛 **Vulnerability Detection**: Detect common vulnerabilities and misconfigurations
- 📊 **CVE Lookup**: Integration with NVD database for known vulnerabilities
- 📈 **Real-time Progress Tracking**: Monitor scan progress in real-time
- 📄 **Comprehensive Reports**: Generate PDF, CSV, and JSON reports
- 👥 **Role-Based Access Control**: Admin, Analyst, and Viewer roles
- 📝 **Audit Logging**: Track all security scanning activities
- 📱 **Responsive Design**: Modern, mobile-friendly interface

## Prerequisites

- Python 3.8+
- Nmap (optional, recommended for richer service detection and larger CIDR scans)
- Redis (optional; required only when running Celery asynchronously)
- PostgreSQL or SQLite (database)

## Installation

### 1. Install System Dependencies

**macOS:**
```bash
brew install nmap redis
```

**Ubuntu/Debian:**
```bash
sudo apt-get install nmap redis-server
```

**Windows:**
1. Install **Python 3.8+** from https://www.python.org/downloads/ (check "Add Python to PATH")
2. Install **Nmap** from https://nmap.org/download.html (optional but recommended)
3. For Redis, choose one option:
   - **Chocolatey**: `choco install redis-64` then `redis-server`
   - **Memurai** (Redis-compatible): https://www.memurai.com/
   - **WSL2**: `sudo apt-get install redis-server && sudo service redis-server start`
   - **No Redis** (simplest): Set `CELERY_TASK_ALWAYS_EAGER=True` in `.env` — scans run synchronously without a separate worker

### Windows Quick Start

Run the automated setup script (double-click or run from Command Prompt):
```bat
setup.bat
```

Then follow the on-screen instructions. If you don't have Redis, add this to your `.env`:
```
CELERY_TASK_ALWAYS_EAGER=True
```
Then start with just `python manage.py runserver` — no Celery worker needed.

> **Celery on Windows**: If you do run Celery with Redis, use `--pool=solo`:
> ```bat
> celery -A config worker -l info --pool=solo
> ```

---

### 2. Open the Project Directory

```bash
cd /path/to/saera
```

### 3. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 4. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 5. Environment Configuration

Copy the example environment file and configure:

```bash
cp .env.example .env
```

Edit `.env` and set your configuration:
- `SECRET_KEY`: Django secret key (generate a new one)
- `DEBUG`: Set to `False` in production
- `DB_NAME`, `DB_USER`, `DB_PASSWORD`: (Optional) PostgreSQL credentials for the production kernel
- `REDIS_URL`: Redis connection URL
- `NVD_API_KEY`: Optional NVD API key for CVE lookups

## 🗄️ Database: PostgreSQL Migration

The SAERA platform is built with a **Hybrid Database Engine**. By default, it uses **SQLite** for zero-config local development. To shift to the professional **PostgreSQL** kernel:

1. **Install PostgreSQL**: Download from [postgresql.org](https://www.postgresql.org/download/windows/).
2. **Create Database**: Create a new database named `netvuln_db`.
3. **Update .env**:
   ```env
   DB_NAME=netvuln_db
   DB_USER=your_postgres_user
   DB_PASSWORD=your_password
   DB_HOST=localhost
   DB_PORT=5432
   ```
4. **Run Setup**: Execute `setup.bat`. The script will automatically detect the Postgres credentials and migrate the data. If the connection fails, it will safely fallback to SQLite.

## 🔌 The "Backend Limb" (API Documentation)

To demonstrate the independence of the backend engine from the "Midnight Aurora" GUI, SAERA provides a dedicated **API Limb**:

- **Swagger UI**: `http://localhost:8000/api/schema/swagger-ui/`
- **ReDoc UI**: `http://localhost:8000/api/schema/redoc/`
- **OpenAPI Schema**: `http://localhost:8000/api/schema/`

This technical interface allows direct interaction with the system's relational data registry via JSON, proving the backend is a separate, functional entity.

### 6. Database Setup

```bash
python manage.py makemigrations
python manage.py migrate
```

### 7. Create Superuser

```bash
python manage.py createsuperuser
```

### 8. Collect Static Files

```bash
python manage.py collectstatic --noinput
```

## Running the Application

### 1. Start Django Development Server

For the simplest local setup, keep `CELERY_TASK_ALWAYS_EAGER=True` in `.env` and run:

```bash
python manage.py runserver
```

Scans will run synchronously in the Django process. This works without Redis or a separate Celery worker.

### 2. Optional: Start Redis for Async Scans

**macOS:**
```bash
brew services start redis
```

**Ubuntu/Debian:**
```bash
sudo systemctl start redis-server
```

Set `CELERY_TASK_ALWAYS_EAGER=False` in `.env`, then start a Celery worker.

### 3. Start Celery Worker

In a new terminal:

**macOS/Linux:**
```bash
source venv/bin/activate
celery -A config worker -l info
```

**Windows:**
```bat
venv\Scripts\activate
celery -A config worker -l info --pool=solo
```

### 4. Start Celery Beat (Optional - for scheduled tasks)

In another terminal:
```bash
source venv/bin/activate
celery -A config beat -l info
```

### 5. Start Django Development Server (Async Mode)

```bash
python manage.py runserver
```

Access the application at `http://localhost:8000`

## Usage

1. **Login**: Use the superuser credentials you created
2. **Create a Scan**: Navigate to "New Scan" and enter target information
3. **Monitor Progress**: Watch real-time scan progress
4. **View Results**: Review detected vulnerabilities and open ports
5. **Generate Reports**: Export results in PDF, CSV, or JSON format

## Security Considerations

⚠️ **IMPORTANT**: This tool should only be used on networks you own or have explicit permission to test. Unauthorized vulnerability scanning may violate laws and regulations.

- Always obtain written permission before scanning
- Respect rate limits and avoid overwhelming target systems
- Keep scan results confidential and secure
- Use strong authentication and access controls
- Regularly update the application and dependencies

## Project Structure

```
├── config/                 # Django project configuration
├── apps/
│   ├── accounts/          # User authentication and authorization
│   ├── scanner/           # Core scanning functionality
│   ├── reports/           # Report generation
│   └── dashboard/         # Main dashboard
├── static/                # CSS, JavaScript, images
├── templates/             # HTML templates
├── media/                 # Generated reports and uploads
└── manage.py              #Django management script
```

## API Endpoints

- `/scanner/` - Scan management
- `/scanner/create/` - Create new scan
- `/scanner/<id>/progress/` - Scan progress page
- `/scanner/api/progress/<id>/` - Progress API (JSON)
- `/scanner/vulnerabilities/` - Vulnerability list
- `/reports/` - Report management
- `/reports/generate/<scan_id>/` - Generate report
- `/reports/download/<report_id>/` - Download report

## Technologies Used

- **Backend**: Django 4.2, Celery, Redis
- **Scanning**: python-nmap, requests
- **Reports**: ReportLab (PDF), CSV, JSON
- **Frontend**: Bootstrap 5, Chart.js, Vanilla JavaScript
- **Database**: SQLite (dev) / PostgreSQL (prod)

## Contributing

This is a security assessment tool. Contributions should focus on:
- Improving vulnerability detection accuracy
- Adding new scan types and modules
- Enhancing report generation
- Security improvements and bug fixes

## License

This project is for educational and authorized security testing purposes only.

## Disclaimer

This tool is provided "as is" without warranty of any kind. The developers are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting security assessments.

## Support

For issues, questions, or contributions, please refer to the project documentation or contact the development team.

---

**Remember: Ethical hacking and responsible disclosure are paramount. Always operate within legal and ethical boundaries.**
"# SAERA-2.0" 
