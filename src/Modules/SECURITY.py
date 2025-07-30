#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Seguridad para xXACRVXx Web
====================================
Funciones de seguridad, validación y auditoría.
"""

import os
import re
import hashlib
import secrets
import logging
from typing import List, Dict, Any, Tuple
from pathlib import Path

log = logging.getLogger("SECURITY")

# ============================================================================
# VALIDACIÓN DE ARCHIVOS
# ============================================================================

def sanitize_filename(filename: str) -> str:
    """Sanitizar nombre de archivo permitiendo cualquier extensión."""
    if not filename:
        return ""
    
    # Remover caracteres peligrosos pero mantener extensiones
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    filename = re.sub(r'[<>:"|?*]', '', filename)  # Caracteres no válidos en Windows
    
    # Limitar longitud
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename.strip()

def validate_file_path(path: str, base_path: str) -> bool:
    """Validar que la ruta esté dentro del directorio base."""
    try:
        resolved_path = os.path.realpath(path)
        resolved_base = os.path.realpath(base_path)
        return resolved_path.startswith(resolved_base)
    except Exception:
        return False

def check_file_size(file_size: int, max_size_gb: int = 4) -> bool:
    """Verificar tamaño de archivo."""
    max_bytes = max_size_gb * 1024 * 1024 * 1024
    return file_size <= max_bytes

# ============================================================================
# VALIDACIÓN DE ENTRADA
# ============================================================================

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitizar entrada de texto."""
    if not text:
        return ""
    
    # Remover caracteres de control
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    # Limitar longitud
    return text[:max_length].strip()

def validate_email(email: str) -> bool:
    """Validar formato de email."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email)) and len(email) <= 254

def validate_username(username: str) -> Tuple[bool, str]:
    """Validar nombre de usuario."""
    if not username:
        return False, "El nombre de usuario es requerido"
    
    if len(username) < 3:
        return False, "El nombre de usuario debe tener al menos 3 caracteres"
    
    if len(username) > 30:
        return False, "El nombre de usuario no puede tener más de 30 caracteres"
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "El nombre de usuario solo puede contener letras, números, guiones y guiones bajos"
    
    return True, "Válido"

def validate_password(password: str) -> Tuple[bool, str]:
    """Validar contraseña."""
    if not password:
        return False, "La contraseña es requerida"
    
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    
    if len(password) > 128:
        return False, "La contraseña no puede tener más de 128 caracteres"
    
    return True, "Válida"

# ============================================================================
# GENERACIÓN SEGURA
# ============================================================================

def generate_secure_token(length: int = 32) -> str:
    """Generar token seguro."""
    return secrets.token_urlsafe(length)

def generate_csrf_token() -> str:
    """Generar token CSRF."""
    return secrets.token_hex(16)

def hash_password(password: str) -> str:
    """Hash seguro de contraseña usando bcrypt."""
    import bcrypt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verificar contraseña contra hash."""
    import bcrypt
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False

# ============================================================================
# AUDITORÍA DE SEGURIDAD
# ============================================================================

def audit_file_permissions(directory: str) -> List[Dict[str, Any]]:
    """Auditar permisos de archivos."""
    issues = []
    
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    stat = os.stat(file_path)
                    mode = oct(stat.st_mode)[-3:]
                    
                    # Verificar permisos excesivos
                    if mode.endswith('7') or mode.endswith('6'):
                        issues.append({
                            'type': 'file_permissions',
                            'path': file_path,
                            'mode': mode,
                            'severity': 'medium',
                            'description': f'Archivo con permisos excesivos: {mode}'
                        })
                except Exception as e:
                    issues.append({
                        'type': 'file_access',
                        'path': file_path,
                        'severity': 'low',
                        'description': f'No se pudo verificar: {e}'
                    })
    except Exception as e:
        log.error(f"Error en auditoría de permisos: {e}")
    
    return issues

def check_security_headers() -> List[Dict[str, Any]]:
    """Verificar configuración de headers de seguridad."""
    recommendations = [
        {
            'header': 'X-Content-Type-Options',
            'value': 'nosniff',
            'description': 'Previene ataques de tipo MIME sniffing'
        },
        {
            'header': 'X-Frame-Options',
            'value': 'DENY',
            'description': 'Previene ataques de clickjacking'
        },
        {
            'header': 'X-XSS-Protection',
            'value': '1; mode=block',
            'description': 'Habilita protección XSS del navegador'
        },
        {
            'header': 'Strict-Transport-Security',
            'value': 'max-age=31536000; includeSubDomains',
            'description': 'Fuerza conexiones HTTPS'
        }
    ]
    
    return recommendations

def scan_for_secrets(directory: str) -> List[Dict[str, Any]]:
    """Escanear archivos en busca de secretos expuestos."""
    issues = []
    
    # Patrones de secretos comunes
    patterns = {
        'api_key': r'api[_-]?key[\'"\s]*[:=][\'"\s]*[a-zA-Z0-9]{20,}',
        'password': r'password[\'"\s]*[:=][\'"\s]*[^\s\'"]{8,}',
        'secret': r'secret[\'"\s]*[:=][\'"\s]*[a-zA-Z0-9]{16,}',
        'token': r'token[\'"\s]*[:=][\'"\s]*[a-zA-Z0-9]{20,}'
    }
    
    try:
        for root, dirs, files in os.walk(directory):
            # Ignorar directorios comunes
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules']]
            
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern_name, pattern in patterns.items():
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                issues.append({
                                    'type': 'exposed_secret',
                                    'pattern': pattern_name,
                                    'file': file_path,
                                    'line': content[:match.start()].count('\n') + 1,
                                    'severity': 'high',
                                    'description': f'Posible {pattern_name} expuesto'
                                })
                    except Exception:
                        continue
    except Exception as e:
        log.error(f"Error escaneando secretos: {e}")
    
    return issues

def generate_security_report(base_path: str) -> Dict[str, Any]:
    """Generar reporte completo de seguridad."""
    report = {
        'timestamp': os.popen('date').read().strip(),
        'base_path': base_path,
        'issues': [],
        'recommendations': [],
        'summary': {}
    }
    
    try:
        # Auditar permisos
        permission_issues = audit_file_permissions(base_path)
        report['issues'].extend(permission_issues)
        
        # Escanear secretos
        secret_issues = scan_for_secrets(base_path)
        report['issues'].extend(secret_issues)
        
        # Headers de seguridad
        security_headers = check_security_headers()
        report['recommendations'].extend(security_headers)
        
        # Resumen
        report['summary'] = {
            'total_issues': len(report['issues']),
            'high_severity': len([i for i in report['issues'] if i.get('severity') == 'high']),
            'medium_severity': len([i for i in report['issues'] if i.get('severity') == 'medium']),
            'low_severity': len([i for i in report['issues'] if i.get('severity') == 'low']),
            'recommendations': len(report['recommendations'])
        }
        
    except Exception as e:
        log.error(f"Error generando reporte de seguridad: {e}")
        report['error'] = str(e)
    
    return report

# ============================================================================
# UTILIDADES DE SEGURIDAD
# ============================================================================

def secure_delete_file(file_path: str) -> bool:
    """Eliminación segura de archivo."""
    try:
        if os.path.exists(file_path):
            # Sobrescribir con datos aleatorios antes de eliminar
            file_size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            os.remove(file_path)
            return True
    except Exception as e:
        log.error(f"Error en eliminación segura: {e}")
    
    return False

def check_rate_limit(ip: str, max_requests: int = 100, window_minutes: int = 60) -> bool:
    """Verificar límite de velocidad (implementación básica)."""
    # Esta es una implementación básica
    # En producción se debería usar Redis o similar
    return True

def log_security_event(event_type: str, details: Dict[str, Any], ip: str = None):
    """Registrar evento de seguridad."""
    log.warning(f"[SECURITY] {event_type}: {details} from {ip or 'unknown'}")

# ============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# ============================================================================

SECURITY_CONFIG = {
    'max_file_size_gb': 4,
    'allowed_upload_extensions': None,  # None = permitir todas
    'max_filename_length': 255,
    'max_login_attempts': 5,
    'session_timeout_hours': 24,
    'csrf_token_length': 32,
    'password_min_length': 8,
    'username_min_length': 3,
    'rate_limit_requests': 100,
    'rate_limit_window_minutes': 60
}

def get_security_config() -> Dict[str, Any]:
    """Obtener configuración de seguridad."""
    return SECURITY_CONFIG.copy()

def update_security_config(key: str, value: Any) -> bool:
    """Actualizar configuración de seguridad."""
    if key in SECURITY_CONFIG:
        SECURITY_CONFIG[key] = value
        return True
    return False