import os, traceback
import platform
import psutil
import logging
import time
import socket

try:
    from dotenv import load_dotenv
    load_dotenv("config.env") # carga las variables de entorno desde el archivo .env
except ImportError:
    pass  # dotenv no disponible, usar variables de entorno del sistema

log = logging.getLogger("CONFIG")

SECRET = os.getenv("SECRET_KEY")

# Variables globales para el tiempo de inicio
START_TIME = time.time()

MY_OS = platform.system()
SYSTEM_PATH = os.getcwd()

UPLOAD_PATH = "uploads"


RUTE = os.path.join(SYSTEM_PATH,UPLOAD_PATH)



def Free_Space():
    disk_usage = psutil.disk_usage(SYSTEM_PATH)
    disk_space = disk_usage.free / 1024**2
    if disk_space >= 1024:
        the_space = round(disk_space / 1024, 2)
        return f"{the_space}GB"
    else:
        the_space = round(disk_space, 2)
        return f"{the_space}MB"




# Cache para información estática del sistema
_system_info_cache = None
_network_info_cache = None
_network_cache_time = 0



def get_enhanced_system_stats():
    """Estadísticas del sistema expandidas multiplataforma"""
    global _system_info_cache, _network_info_cache, _network_cache_time
    
    try:
        # Información estática del sistema (solo se calcula una vez)
        if _system_info_cache is None:
            _system_info_cache = {
                'os_name': f"{MY_OS} {platform.release()}",
                'python_version': platform.python_version(),
                'hostname': platform.node()
            }
        
        # Información de red (cache de 5 minutos)
        current_time = time.time()
        if _network_info_cache is None or (current_time - _network_cache_time) > 300:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                _network_info_cache = {
                    'local_ip': local_ip,
                    'external_ip': local_ip
                }
                _network_cache_time = current_time
            except:
                _network_info_cache = {
                    'local_ip': '127.0.0.1',
                    'external_ip': '127.0.0.1'
                }
        
        # Detectar ruta de disco según SO
        disk_path = 'C:\\' if MY_OS == 'Windows' else '/'
        
        # Estadísticas dinámicas
        stats = {
            'disk_usage': psutil.disk_usage(disk_path).percent,
            'memory_usage': psutil.virtual_memory().percent,
            'cpu_usage': psutil.cpu_percent(interval=0.1)
        }
        
        # Agregar información estática
        stats.update(_system_info_cache)
        stats.update(_network_info_cache)
        
        # Estadísticas de proceso actual
        try:
            process = psutil.Process()
            stats.update({
                'process_memory': process.memory_info().rss / 1024 / 1024,  # MB
                'process_cpu': process.cpu_percent(),
                'threads_count': process.num_threads(),
                'network_connections': len(psutil.net_connections())
            })
        except Exception as proc_error:
            log.debug(f"Error obteniendo estadísticas de proceso: {proc_error}")
            stats.update({
                'process_memory': 0,
                'process_cpu': 0,
                'threads_count': 0,
                'network_connections': 0
            })
        
        return stats
        
    except Exception as e:
        log.warning(f"Error obteniendo estadísticas: {e}")
        return {
            'disk_usage': 0, 'memory_usage': 0, 'cpu_usage': 0,
            'os_name': f"{MY_OS} {platform.release() if hasattr(platform, 'release') else 'Desconocido'}",
            'python_version': platform.python_version(),
            'network_connections': 0, 'process_memory': 0, 
            'process_cpu': 0, 'threads_count': 0,
            'hostname': 'Desconocido', 'local_ip': 'No disponible',
            'external_ip': 'No disponible'
        }



def get_uptime():
    """Obtener tiempo de actividad del servidor"""
    try:
        uptime_seconds = time.time() - START_TIME
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
    except:
        return "0h 0m"

def count_user_files():
    """Contar archivos de usuarios"""
    try:
        if not os.path.exists(RUTE):
            return 0
        total = 0
        for d in os.listdir(RUTE):
            dir_path = os.path.join(RUTE, d)
            if os.path.isdir(dir_path):
                for root, dirs, files in os.walk(dir_path):
                    total += len(files)
        return total
    except Exception as e:
        log.warning(f"Error contando archivos: {e}")
        return 0

def get_disk_usage():
    """Obtener uso de disco"""
    try:
        disk_path = 'C:\\' if MY_OS == 'Windows' else '/'
        return round(psutil.disk_usage(disk_path).percent, 1)
    except:
        return 0

def get_memory_usage():
    """Obtener uso de memoria RAM del sistema"""
    try:
        memory = psutil.virtual_memory()
        return round(memory.percent, 1)
    except Exception as e:
        log.warning(f"Error obteniendo uso de memoria: {e}")
        return 0

def get_memory_info():
    """Obtener información detallada de memoria"""
    try:
        memory = psutil.virtual_memory()
        return {
            'total': round(memory.total / 1024 / 1024 / 1024, 2),  # GB
            'available': round(memory.available / 1024 / 1024 / 1024, 2),  # GB
            'used': round(memory.used / 1024 / 1024 / 1024, 2),  # GB
            'percent': round(memory.percent, 1)
        }
    except Exception as e:
        log.warning(f"Error obteniendo información de memoria: {e}")
        return {'total': 0, 'available': 0, 'used': 0, 'percent': 0}

def get_system_config():
    """Obtener configuración del sistema"""
    return {
        'admin_email': os.getenv('EMAIL_WEBMASTER', '').strip("' "),
        'smtp_user': os.getenv('EMAIL_USER', '').strip("' "),
        'debug_mode': os.getenv('DEBUG', 'False').lower() == 'true',
        'base_url': os.getenv('BASE_URL', 'https://xxacrvxx.ydns.eu').strip("' "),
        'max_file_size': int(os.getenv('MAX_FILE_SIZE_GB', '4')),
        'email_verification_mode': int(os.getenv('EMAIL_VERIFICATION_MODE', '1')),
        'maintenance_mode': os.getenv('MAINTENANCE_MODE', 'False').lower() == 'true',
        'registration_enabled': os.getenv('REGISTRATION_ENABLED', 'True').lower() == 'true',
        'max_login_attempts': int(os.getenv('MAX_LOGIN_ATTEMPTS', '5')),
        'remember_me_days': int(os.getenv('REMEMBER_ME_DAYS', '30')),
        'download_timeout': int(os.getenv('DOWNLOAD_TIMEOUT_SECONDS', '300')),
        'session_timeout_hours': int(os.getenv('SESSION_TIMEOUT_HOURS', '24')),
        'auto_backup_enabled': os.getenv('AUTO_BACKUP_ENABLED', 'False').lower() == 'true',
        'thumbnail_quality': int(os.getenv('THUMBNAIL_QUALITY', '85')),
        'db_host': os.getenv('HOST_DB', 'localhost').strip("' "),
        'db_port': os.getenv('PORT_DB', '5432').strip("' "),
        'db_name': os.getenv('NAME_DB', '').strip("' ")
    }

def get_env_status():
    """Obtener estado de variables de entorno"""
    return [
        {'name': 'DEBUG', 'value': os.getenv('DEBUG', 'False').strip("' "), 'set': bool(os.getenv('DEBUG')), 'sensitive': False},
        {'name': 'SECRET_KEY', 'value': '***', 'set': bool(os.getenv('SECRET_KEY')), 'sensitive': True},
        {'name': 'EMAIL_WEBMASTER', 'value': os.getenv('EMAIL_WEBMASTER', '').strip("' "), 'set': bool(os.getenv('EMAIL_WEBMASTER')), 'sensitive': False},
        {'name': 'EMAIL_USER', 'value': os.getenv('EMAIL_USER', '').strip("' "), 'set': bool(os.getenv('EMAIL_USER')), 'sensitive': False},
        {'name': 'EMAIL_PASSW', 'value': '***', 'set': bool(os.getenv('EMAIL_PASSW')), 'sensitive': True},
        {'name': 'EMAIL_VERIFICATION_MODE', 'value': os.getenv('EMAIL_VERIFICATION_MODE', '1').strip("' "), 'set': bool(os.getenv('EMAIL_VERIFICATION_MODE')), 'sensitive': False},
        {'name': 'MAINTENANCE_MODE', 'value': os.getenv('MAINTENANCE_MODE', 'False').strip("' "), 'set': bool(os.getenv('MAINTENANCE_MODE')), 'sensitive': False},
        {'name': 'REGISTRATION_ENABLED', 'value': os.getenv('REGISTRATION_ENABLED', 'True').strip("' "), 'set': bool(os.getenv('REGISTRATION_ENABLED')), 'sensitive': False},
        {'name': 'MAX_LOGIN_ATTEMPTS', 'value': os.getenv('MAX_LOGIN_ATTEMPTS', '5').strip("' "), 'set': bool(os.getenv('MAX_LOGIN_ATTEMPTS')), 'sensitive': False},
        {'name': 'REMEMBER_ME_DAYS', 'value': os.getenv('REMEMBER_ME_DAYS', '30').strip("' "), 'set': bool(os.getenv('REMEMBER_ME_DAYS')), 'sensitive': False},
        {'name': 'DOWNLOAD_TIMEOUT_SECONDS', 'value': os.getenv('DOWNLOAD_TIMEOUT_SECONDS', '300').strip("' "), 'set': bool(os.getenv('DOWNLOAD_TIMEOUT_SECONDS')), 'sensitive': False},
        {'name': 'SESSION_TIMEOUT_HOURS', 'value': os.getenv('SESSION_TIMEOUT_HOURS', '24').strip("' "), 'set': bool(os.getenv('SESSION_TIMEOUT_HOURS')), 'sensitive': False},
        {'name': 'AUTO_BACKUP_ENABLED', 'value': os.getenv('AUTO_BACKUP_ENABLED', 'False').strip("' "), 'set': bool(os.getenv('AUTO_BACKUP_ENABLED')), 'sensitive': False},
        {'name': 'THUMBNAIL_QUALITY', 'value': os.getenv('THUMBNAIL_QUALITY', '85').strip("' "), 'set': bool(os.getenv('THUMBNAIL_QUALITY')), 'sensitive': False},
        {'name': 'HOST_DB', 'value': os.getenv('HOST_DB', '').strip("' "), 'set': bool(os.getenv('HOST_DB')), 'sensitive': False},
        {'name': 'NAME_DB', 'value': os.getenv('NAME_DB', '').strip("' "), 'set': bool(os.getenv('NAME_DB')), 'sensitive': False},
        {'name': 'USERPG_DB', 'value': os.getenv('USERPG_DB', '').strip("' "), 'set': bool(os.getenv('USERPG_DB')), 'sensitive': False},
        {'name': 'PASSWPG_DB', 'value': '***', 'set': bool(os.getenv('PASSWPG_DB')), 'sensitive': True}
    ]

def SPACE_FILE(uss,archive):
    try:
        rute_archive = os.path.join(RUTE,str(uss),str(archive))
        the_file=os.path.getsize((rf'{rute_archive}'))
        f_space = the_file / 1024**2
        if the_file / 1024**1 <= 1024:
            the_space_file = round(the_file / 1024**1, 2)
            return f"{the_space_file}KB"
        elif f_space >= 1024:
            the_space_file = round(f_space / 1024, 2)
            return f"{the_space_file}GB"
        else:
            the_space_file = round(f_space, 2)
            return f"{the_space_file}MB"
    except Exception as e:
        log.error(f"[SPACE_FILE] [ERROR] {e} [{traceback.format_exc()}]")
        return "ERROR"

def get_network_info():
    """Obtener información de red del sistema"""
    try:
        info = {
            'hostname': platform.node(),
            'local_ip': '127.0.0.1',
            'external_ip': 'No disponible',
            'network_interfaces': []
        }
        
        # Obtener IP local
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info['local_ip'] = s.getsockname()[0]
            s.close()
        except:
            pass
        
        # Obtener interfaces de red
        try:
            if hasattr(psutil, 'net_if_addrs'):
                interfaces = psutil.net_if_addrs()
                for interface, addrs in interfaces.items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            info['network_interfaces'].append({
                                'name': interface,
                                'ip': addr.address,
                                'netmask': addr.netmask
                            })
        except:
            pass
        
        return info
    except Exception as e:
        log.warning(f"Error obteniendo información de red: {e}")
        return {
            'hostname': 'Desconocido',
            'local_ip': '127.0.0.1',
            'external_ip': 'No disponible',
            'network_interfaces': []
        }


        






if __name__ == "__main__":
    print(f"SISTEMA OPERATIVO: {MY_OS}")
    print(f"RUTA DEL PATH DEL SERVIDOR: {RUTE}")
    print(f"ESPACIO DISPONIBLE  {Free_Space()}")
