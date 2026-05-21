# NetVuln Installation Guide

## Required Software

- Python 3.11+
- MySQL Server
- pip
- Nmap, optional but recommended

This simplified version uses Python, Django, MySQL, pip, and optional Nmap.

## MySQL Setup

Create the database before running migrations:

```sql
CREATE DATABASE saera_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Update `.env`:

```env
DB_NAME=saera_db
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_HOST=localhost
DB_PORT=3306
```

## Run Project

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/`.