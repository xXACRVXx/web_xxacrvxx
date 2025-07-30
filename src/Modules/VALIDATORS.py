import re
import logging

log = logging.getLogger("VALIDATORS")

def validate_email(email):
    """Validación mejorada de email"""
    if not email or len(email) > 254:
        return False
    
    # Regex más robusta para email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validación de contraseña"""
    if not password:
        return False, "La contraseña es requerida"
    
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if len(password) > 128:  # Límite más razonable
        return False, "La contraseña no puede tener más de 128 caracteres"
    
    return True, "Válida"

def validate_username(username):
    """Validación de nombre de usuario"""
    if not username:
        return False, "El nombre de usuario es requerido"
    
    if len(username) < 3:
        return False, "El nombre de usuario debe tener al menos 3 caracteres"
    
    if len(username) > 30:
        return False, "El nombre de usuario no puede tener más de 30 caracteres"
    
    # No puede ser un email
    if validate_email(username):
        return False, "El usuario no puede ser un correo electrónico"
    
    # Solo letras, números y algunos caracteres especiales
    pattern = r'^[a-zA-Z0-9._-]+$'
    if not re.match(pattern, username):
        return False, "El usuario solo puede contener letras, números, puntos, guiones y guiones bajos"
    
    return True, "Válido"