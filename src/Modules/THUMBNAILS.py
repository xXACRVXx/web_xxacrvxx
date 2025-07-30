import os
import tempfile
import hashlib
import logging
from PIL import Image
import platform

log = logging.getLogger("THUMBNAILS")

# Directorio de miniaturas según el sistema operativo
if platform.system() == "Windows":
    THUMB_DIR = os.path.join(tempfile.gettempdir(), "xxacrvxx_thumbnails")
else:
    THUMB_DIR = os.path.join("/tmp", "xxacrvxx_thumbnails")

# Crear directorio si no existe
os.makedirs(THUMB_DIR, exist_ok=True)

# Tamaño de miniatura
THUMB_SIZE = (200, 200)

# Extensiones de imagen soportadas
IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff'}

def is_image(filename):
    """Verificar si el archivo es una imagen"""
    ext = os.path.splitext(filename.lower())[1]
    return ext in IMAGE_EXTENSIONS

def get_thumbnail_path(file_path, user_id):
    """Generar ruta de miniatura basada en hash del archivo"""
    # Crear hash único basado en ruta del archivo y user_id
    file_hash = hashlib.md5(f"{user_id}_{file_path}".encode()).hexdigest()
    return os.path.join(THUMB_DIR, f"{file_hash}.jpg")

def create_thumbnail(source_path, thumb_path):
    """Crear miniatura de una imagen"""
    try:
        with Image.open(source_path) as img:
            # Convertir a RGB si es necesario
            if img.mode in ('RGBA', 'LA', 'P'):
                img = img.convert('RGB')
            
            # Crear miniatura manteniendo proporción
            img.thumbnail(THUMB_SIZE, Image.Resampling.LANCZOS)
            
            # Guardar miniatura
            img.save(thumb_path, 'JPEG', quality=85, optimize=True)
            return True
    except Exception as e:
        log.error(f"Error creando miniatura: {e}")
        return False

def get_or_create_thumbnail(file_path, user_id):
    """Obtener miniatura existente o crear una nueva"""
    if not is_image(os.path.basename(file_path)):
        return None
    
    if not os.path.exists(file_path):
        return None
    
    thumb_path = get_thumbnail_path(file_path, user_id)
    
    # Si la miniatura existe y es más nueva que el archivo original
    if os.path.exists(thumb_path):
        if os.path.getmtime(thumb_path) >= os.path.getmtime(file_path):
            return thumb_path
    
    # Crear nueva miniatura
    if create_thumbnail(file_path, thumb_path):
        return thumb_path
    
    return None

def cleanup_old_thumbnails(max_age_days=7):
    """Limpiar miniaturas antiguas"""
    try:
        import time
        current_time = time.time()
        max_age_seconds = max_age_days * 24 * 60 * 60
        
        for filename in os.listdir(THUMB_DIR):
            file_path = os.path.join(THUMB_DIR, filename)
            if os.path.isfile(file_path):
                if current_time - os.path.getmtime(file_path) > max_age_seconds:
                    os.remove(file_path)
                    log.debug(f"Miniatura eliminada: {filename}")
    except Exception as e:
        log.error(f"Error limpiando miniaturas: {e}")