#!/usr/bin/env python3
import os
import secrets
from pathlib import Path

def create_config():
    """Crear configuración inicial interactiva."""
    print("🔧 Configuración inicial de xXACRVXx Web\n")
    
    print("📊 Configuración de PostgreSQL:")
    host_db = input("Host [localhost]: ") or "localhost"
    port_db = input("Puerto [5432]: ") or "5432"
    name_db = input("Nombre de la base de datos: ")
    user_db = input("Usuario: ")
    pass_db = input("Contraseña: ")
    
    print("\n📧 Email del administrador:")
    email_webmaster = input("Email: ")
    
    config_content = f"""DEBUG=False
SECRET_KEY={secrets.token_urlsafe(32)}
EMAIL_WEBMASTER={email_webmaster}
HOST_DB={host_db}
PORT_DB={port_db}
NAME_DB={name_db}
USERPG_DB={user_db}
PASSWPG_DB={pass_db}
BASE_URL=http://localhost:9001
EMAIL_VERIFICATION_MODE=1
REGISTRATION_ENABLED=True
MAINTENANCE_MODE=False
MAX_LOGIN_ATTEMPTS=5
MAX_FILE_SIZE_GB=4
REMEMBER_ME_DAYS=30
DOWNLOAD_TIMEOUT_SECONDS=300
SESSION_TIMEOUT_HOURS=24
AUTO_BACKUP_ENABLED=False
THUMBNAIL_QUALITY=85
EMAIL_USER=
EMAIL_PASSW=
"""
    
    Path("config.env").write_text(config_content)
    print(f"\n✅ Configuración creada en config.env")
    return True