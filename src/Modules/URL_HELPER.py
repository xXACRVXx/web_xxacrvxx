import os
from dotenv import load_dotenv

load_dotenv("config.env")

def get_base_url():
    """Obtener URL base desde variable de entorno o usar default"""
    return os.getenv("BASE_URL", "https://xxacrvxx.ydns.eu")

def build_url(path):
    """Construir URL completa"""
    base = get_base_url()
    return f"{base}{path}"