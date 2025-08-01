#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Analíticas Mejorado para xXACRVXx Web
===============================================
Sistema avanzado de métricas con persistencia de 1 año y análisis temporal completo.
"""

import os
import json
import time
import logging
import threading
from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

log = logging.getLogger("ANALYTICS")

# Configuración
DATA_DIR = Path("data/analytics")
STATS_FILE = DATA_DIR / "analytics_data.json"
GEO_CACHE_FILE = DATA_DIR / "geo_cache.json"
BACKUP_DIR = DATA_DIR / "backups"
SAVE_INTERVAL = 300  # 5 minutos
DATA_RETENTION_DAYS = 365  # 1 año de retención

# Thread safety
_lock = threading.RLock()

# Estructura de datos mejorada
_analytics = {
    'meta': {
        'version': '2.1',
        'start_time': time.time(),
        'last_save': time.time(),
        'total_visits': 0
    },
    'visitors': {
        'unique_ips': set(),
        'external_ips': [],  # Solo IPs externas para geolocalización
        'sessions': set(),   # Session IDs únicos
        'unique_users': set(),  # User IDs únicos
        'new_users': set(),     # Usuarios nuevos
        'returning_users': set() # Usuarios que regresan
    },
    'temporal': {
        'hourly': defaultdict(int),      # "2024-01-15_14" -> visits
        'daily': defaultdict(int),       # "2024-01-15" -> visits  
        'monthly': defaultdict(int),     # "2024-01" -> visits
        'yearly': defaultdict(int),      # "2024" -> visits
        'weekdays': defaultdict(int)     # "Monday" -> visits
    },
    'geographic': {
        'countries': defaultdict(int),
        'cities': defaultdict(int),
        'isps': defaultdict(int),
        'timezones': defaultdict(int)
    },
    'technical': {
        'browsers': defaultdict(int),
        'os': defaultdict(int),
        'devices': defaultdict(int),
        'bots': defaultdict(int),
        'resolutions': defaultdict(int),
        'languages': defaultdict(int),
        'connections': defaultdict(int)
    },
    'content': {
        'pages': defaultdict(int),
        'referrers': defaultdict(int),
        'page_categories': defaultdict(int)
    },
    'engagement': {
        'session_pages': defaultdict(int),
        'session_duration': defaultdict(float),
        'bounce_sessions': set(),
        'active_sessions': set()
    },
    'traffic': {
        'referrer_types': defaultdict(int),
        'social_media': defaultdict(int),
        'search_engines': defaultdict(int)
    }
}

_geo_cache = {}
_last_save = time.time()

# Mapeo de ISPs para nombres completos
ISP_MAPPING = {
    'Telefonica': 'Telefónica España',
    'Orange': 'Orange España',
    'Vodafone': 'Vodafone España',
    'MasMovil': 'MásMóvil',
    'Jazztel': 'Jazztel (Orange)',
    'Movistar': 'Movistar (Telefónica)',
    'Pepephone': 'Pepephone',
    'Yoigo': 'Yoigo (MásMóvil)',
    'Euskaltel': 'Euskaltel',
    'R Cable': 'R Cable y Telecomunicaciones',
    'Google': 'Google LLC',
    'Amazon': 'Amazon Web Services',
    'Microsoft': 'Microsoft Corporation',
    'Cloudflare': 'Cloudflare Inc.',
    'OVH': 'OVH SAS',
    'DigitalOcean': 'DigitalOcean LLC',
    'Hetzner': 'Hetzner Online GmbH'
}

def _ensure_dirs():
    """Crear directorios necesarios."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

def _clean_old_data():
    """Limpiar datos antiguos (más de 1 año)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=DATA_RETENTION_DAYS)
    cutoff_str = cutoff.strftime('%Y-%m-%d')
    
    # Limpiar datos diarios antiguos
    old_keys = [k for k in _analytics['temporal']['daily'].keys() if k < cutoff_str]
    for key in old_keys:
        del _analytics['temporal']['daily'][key]
    
    # Limpiar datos horarios antiguos (más de 30 días)
    cutoff_hourly = datetime.now(timezone.utc) - timedelta(days=30)
    cutoff_hourly_str = cutoff_hourly.strftime('%Y-%m-%d')
    old_hourly = [k for k in _analytics['temporal']['hourly'].keys() if k.split('_')[0] < cutoff_hourly_str]
    for key in old_hourly:
        del _analytics['temporal']['hourly'][key]

def _serialize_data() -> Dict[str, Any]:
    """Serializar datos para JSON."""
    data = {}
    for section, content in _analytics.items():
        if section == 'visitors':
            data[section] = {
                'unique_ips': list(content['unique_ips']),
                'external_ips': content['external_ips'],
                'sessions': list(content.get('sessions', set())),
                'unique_users': list(content.get('unique_users', set())),
                'new_users': list(content.get('new_users', set())),
                'returning_users': list(content.get('returning_users', set()))
            }
        elif section == 'engagement':
            data[section] = {}
            for key, value in content.items():
                if isinstance(value, set):
                    data[section][key] = list(value)
                elif isinstance(value, defaultdict):
                    data[section][key] = dict(value)
                else:
                    data[section][key] = value
        else:
            data[section] = {}
            for key, value in content.items():
                if isinstance(value, set):
                    data[section][key] = list(value)
                elif isinstance(value, defaultdict):
                    data[section][key] = dict(value)
                else:
                    data[section][key] = value
    return data

def _deserialize_data(data: Dict[str, Any]):
    """Deserializar datos desde JSON."""
    global _analytics
    
    for section, content in data.items():
        if section == 'visitors':
            _analytics[section]['unique_ips'] = set(content.get('unique_ips', []))
            _analytics[section]['external_ips'] = content.get('external_ips', [])
            _analytics[section]['sessions'] = set(content.get('sessions', []))
            _analytics[section]['unique_users'] = set(content.get('unique_users', []))
            _analytics[section]['new_users'] = set(content.get('new_users', []))
            _analytics[section]['returning_users'] = set(content.get('returning_users', []))
        elif section == 'engagement':
            for key, value in content.items():
                if key in ['bounce_sessions', 'active_sessions']:
                    _analytics[section][key] = set(value) if isinstance(value, list) else value
                elif key in ['session_pages', 'session_duration']:
                    _analytics[section][key] = defaultdict(int if key == 'session_pages' else float, value)
                else:
                    _analytics[section][key] = value
        elif section in _analytics:
            for key, value in content.items():
                if key in ['hourly', 'daily', 'monthly', 'yearly', 'weekdays', 'countries', 'cities', 
                          'isps', 'timezones', 'browsers', 'os', 'devices', 'bots', 'pages', 'referrers',
                          'page_categories', 'referrer_types', 'social_media', 'search_engines',
                          'resolutions', 'languages', 'connections']:
                    _analytics[section][key] = defaultdict(int, value)
                else:
                    _analytics[section][key] = value

def save_analytics_data():
    """Guardar datos con backup automático y validación."""
    try:
        with _lock:
            _ensure_dirs()
            _clean_old_data()
            
            # Serializar datos
            serialized_data = _serialize_data()
            
            # Validar que los datos se pueden serializar correctamente
            try:
                json.dumps(serialized_data)
            except (TypeError, ValueError) as e:
                log.error(f"Error serializando datos: {e}")
                return False
            
            # Backup si existe archivo previo
            if STATS_FILE.exists():
                backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                backup_path = BACKUP_DIR / backup_name
                try:
                    STATS_FILE.rename(backup_path)
                except Exception as e:
                    log.warning(f"Error creando backup: {e}")
                
                # Limpiar backups antiguos (mantener solo 10)
                try:
                    backups = sorted(BACKUP_DIR.glob("backup_*.json"))
                    for old_backup in backups[:-10]:
                        old_backup.unlink()
                except Exception as e:
                    log.warning(f"Error limpiando backups antiguos: {e}")
            
            # Guardar datos actuales de forma atómica
            temp_file = STATS_FILE.with_suffix('.tmp')
            try:
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(serialized_data, f, indent=2, ensure_ascii=False)
                
                # Validar que el archivo temporal es válido
                if _validate_and_repair_json(temp_file):
                    temp_file.rename(STATS_FILE)
                else:
                    temp_file.unlink()
                    log.error("Archivo temporal inválido - no se guardó")
                    return False
            except Exception as e:
                if temp_file.exists():
                    temp_file.unlink()
                raise e
            
            # Guardar cache geo de forma similar
            if _geo_cache:
                geo_temp_file = GEO_CACHE_FILE.with_suffix('.tmp')
                try:
                    with open(geo_temp_file, 'w', encoding='utf-8') as f:
                        json.dump(_geo_cache, f, indent=2, ensure_ascii=False)
                    
                    if _validate_and_repair_json(geo_temp_file):
                        geo_temp_file.rename(GEO_CACHE_FILE)
                    else:
                        geo_temp_file.unlink()
                        log.warning("Cache geo temporal inválido")
                except Exception as e:
                    if geo_temp_file.exists():
                        geo_temp_file.unlink()
                    log.warning(f"Error guardando cache geo: {e}")
            
            _analytics['meta']['last_save'] = time.time()
            log.info("Datos de analytics guardados correctamente")
            return True
            
    except Exception as e:
        log.error(f"Error guardando analytics: {e}")
        return False

def _validate_and_repair_json(file_path):
    """Validar y reparar archivo JSON si es necesario."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            json.load(f)
        return True
    except json.JSONDecodeError as e:
        log.warning(f"Archivo JSON corrupto en {file_path}: {e}")
        # Crear backup del archivo corrupto
        backup_path = file_path.with_suffix('.corrupted.backup')
        file_path.rename(backup_path)
        log.info(f"Backup del archivo corrupto creado: {backup_path}")
        return False
    except Exception as e:
        log.error(f"Error validando JSON: {e}")
        return False

def load_analytics_data():
    """Cargar datos desde disco."""
    try:
        with _lock:
            if STATS_FILE.exists():
                # Validar archivo antes de cargar
                if _validate_and_repair_json(STATS_FILE):
                    with open(STATS_FILE, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        _deserialize_data(data)
                    log.info(f"Analytics cargados: {_analytics['meta']['total_visits']} visitas")
                else:
                    log.warning("Archivo de analytics corrupto - iniciando con datos limpios")
            
            if GEO_CACHE_FILE.exists():
                global _geo_cache
                if _validate_and_repair_json(GEO_CACHE_FILE):
                    with open(GEO_CACHE_FILE, 'r', encoding='utf-8') as f:
                        _geo_cache = json.load(f)
                    log.info(f"Cache geo cargado: {len(_geo_cache)} IPs")
                else:
                    log.warning("Cache geo corrupto - iniciando limpio")
                    _geo_cache = {}
                
    except Exception as e:
        log.error(f"Error cargando analytics: {e}")

def _auto_save():
    """Auto-guardado si es necesario."""
    global _last_save
    if time.time() - _last_save > SAVE_INTERVAL:
        save_analytics_data()
        _last_save = time.time()

def _parse_user_agent(ua: str) -> Dict[str, str]:
    """Parsear user agent optimizado."""
    ua_lower = ua.lower()
    
    # Navegadores
    if 'edg' in ua_lower:
        browser = 'Edge'
    elif 'chrome' in ua_lower and 'edg' not in ua_lower:
        browser = 'Chrome'
    elif 'firefox' in ua_lower:
        browser = 'Firefox'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        browser = 'Safari'
    elif 'opera' in ua_lower:
        browser = 'Opera'
    else:
        browser = 'Otro'
    
    # OS
    if 'windows' in ua_lower:
        os_name = 'Windows'
    elif 'mac' in ua_lower or 'darwin' in ua_lower:
        os_name = 'macOS'
    elif 'linux' in ua_lower:
        os_name = 'Linux'
    elif 'android' in ua_lower:
        os_name = 'Android'
    elif 'iphone' in ua_lower or 'ipad' in ua_lower:
        os_name = 'iOS'
    else:
        os_name = 'Otro'
    
    # Dispositivo
    if 'mobile' in ua_lower or 'android' in ua_lower or 'iphone' in ua_lower:
        device = 'Móvil'
    elif 'tablet' in ua_lower or 'ipad' in ua_lower:
        device = 'Tablet'
    else:
        device = 'Escritorio'
    
    is_bot = any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper'])
    
    return {'browser': browser, 'os': os_name, 'device': device, 'is_bot': is_bot}

def record_visit(ip: str, user_agent: str = '', page: str = '', referrer: str = '', 
                session_id: str = '', screen_resolution: str = '', language: str = '', 
                user_timezone: str = '', connection_type: str = '', user_id: str = '', 
                is_returning: bool = False, pages_viewed: int = 1):
    """Registrar visita con estructura temporal mejorada y datos adicionales de cookies."""
    try:
        with _lock:
            if not ip or ip == 'unknown':
                return
            
            # Sanitizar IP
            clean_ip = ip.replace('\n', '').replace('\r', '')[:45]
            
            # Incrementar contadores
            _analytics['meta']['total_visits'] += 1
            _analytics['visitors']['unique_ips'].add(clean_ip)
            
            # Almacenar IPs externas para geolocalización
            if not clean_ip.startswith(('127.', '192.168.', '10.', '172.')):
                if clean_ip not in _analytics['visitors']['external_ips']:
                    _analytics['visitors']['external_ips'].append(clean_ip)
            
            # Registrar tiempo con estructura mejorada
            now = datetime.now(timezone.utc)
            hour_key = now.strftime('%Y-%m-%d_%H')  # "2024-01-15_14"
            day_key = now.strftime('%Y-%m-%d')      # "2024-01-15"
            month_key = now.strftime('%Y-%m')       # "2024-01"
            year_key = now.strftime('%Y')           # "2024"
            weekday = now.strftime('%A')            # "Monday"
            
            _analytics['temporal']['hourly'][hour_key] += 1
            _analytics['temporal']['daily'][day_key] += 1
            _analytics['temporal']['monthly'][month_key] += 1
            _analytics['temporal']['yearly'][year_key] += 1
            
            # Nuevas métricas temporales
            _analytics['temporal'].setdefault('weekdays', defaultdict(int))
            _analytics['temporal']['weekdays'][weekday] += 1
            
            # Procesar user agent
            if user_agent:
                ua_data = _parse_user_agent(user_agent)
                _analytics['technical']['browsers'][ua_data['browser']] += 1
                _analytics['technical']['os'][ua_data['os']] += 1
                _analytics['technical']['devices'][ua_data['device']] += 1
                
                if ua_data['is_bot']:
                    _analytics['technical']['bots'][user_agent[:50]] += 1
            
            # Datos adicionales de cookies
            if screen_resolution:
                _analytics['technical'].setdefault('resolutions', defaultdict(int))
                _analytics['technical']['resolutions'][screen_resolution] += 1
            
            if language:
                _analytics['technical'].setdefault('languages', defaultdict(int))
                _analytics['technical']['languages'][language] += 1
            
            if user_timezone and user_timezone != 'unknown':
                _analytics['geographic']['timezones'][user_timezone] += 1
            
            if connection_type and connection_type != 'unknown':
                _analytics['technical'].setdefault('connections', defaultdict(int))
                _analytics['technical']['connections'][connection_type] += 1
            
            # Registrar session_id para análisis de sesiones
            if session_id:
                _analytics['visitors'].setdefault('sessions', set())
                _analytics['visitors']['sessions'].add(session_id)
                
                # Métricas de sesión
                _analytics.setdefault('engagement', {
                    'session_pages': defaultdict(int),
                    'session_duration': defaultdict(float),
                    'bounce_sessions': set(),
                    'active_sessions': set()
                })
                
                _analytics['engagement']['session_pages'][session_id] = pages_viewed
                if pages_viewed == 1:
                    _analytics['engagement']['bounce_sessions'].add(session_id)
                else:
                    _analytics['engagement']['bounce_sessions'].discard(session_id)
                    _analytics['engagement']['active_sessions'].add(session_id)
            
            # Usuarios únicos y recurrentes
            if user_id:
                _analytics['visitors'].setdefault('unique_users', set())
                _analytics['visitors']['unique_users'].add(user_id)
                
                if is_returning:
                    _analytics['visitors'].setdefault('returning_users', set())
                    _analytics['visitors']['returning_users'].add(user_id)
                else:
                    _analytics['visitors'].setdefault('new_users', set())
                    _analytics['visitors']['new_users'].add(user_id)
            
            # Contenido (solo si no es ruta administrativa)
            if page and not any(page.startswith(prefix) for prefix in ['/admin/', '/api/', '/static/']):
                _analytics['content']['pages'][page] += 1
                
                # Análisis de rutas populares
                _analytics['content'].setdefault('page_categories', defaultdict(int))
                if page.startswith('/blog'):
                    _analytics['content']['page_categories']['Blog'] += 1
                elif page in ['/', '/index']:
                    _analytics['content']['page_categories']['Home'] += 1
                elif page.startswith('/cloud') or page.startswith('/download') or page.startswith('/upload'):
                    _analytics['content']['page_categories']['Cloud'] += 1
                elif page.startswith('/about') or page.startswith('/team') or page.startswith('/portfolio'):
                    _analytics['content']['page_categories']['About'] += 1
                elif page.startswith('/contact') or page.startswith('/services'):
                    _analytics['content']['page_categories']['Contact'] += 1
                else:
                    _analytics['content']['page_categories']['Other'] += 1
            
            # Análisis de referrers
            if referrer and referrer != '-':
                _analytics['content']['referrers'][referrer] += 1
                
                # Categorizar referrers
                _analytics.setdefault('traffic', {
                    'referrer_types': defaultdict(int),
                    'social_media': defaultdict(int),
                    'search_engines': defaultdict(int)
                })
                
                referrer_lower = referrer.lower()
                if any(social in referrer_lower for social in ['facebook', 'twitter', 'instagram', 'linkedin', 'telegram']):
                    _analytics['traffic']['referrer_types']['Social Media'] += 1
                    for social in ['facebook', 'twitter', 'instagram', 'linkedin', 'telegram']:
                        if social in referrer_lower:
                            _analytics['traffic']['social_media'][social.title()] += 1
                            break
                elif any(search in referrer_lower for search in ['google', 'bing', 'yahoo', 'duckduckgo']):
                    _analytics['traffic']['referrer_types']['Search Engine'] += 1
                    for search in ['google', 'bing', 'yahoo', 'duckduckgo']:
                        if search in referrer_lower:
                            _analytics['traffic']['search_engines'][search.title()] += 1
                            break
                else:
                    _analytics['traffic']['referrer_types']['Direct/Other'] += 1
            else:
                _analytics.setdefault('traffic', {'referrer_types': defaultdict(int)})
                _analytics['traffic']['referrer_types']['Direct'] += 1
            
            _auto_save()
            
    except Exception as e:
        log.error(f"Error registrando visita: {e}")

def _geolocate_ips():
    """Geolocalizar IPs pendientes."""
    try:
        import requests
    except ImportError:
        log.warning("Requests no disponible para geolocalización")
        return
    
    with _lock:
        pending = [ip for ip in _analytics['visitors']['external_ips'] if ip not in _geo_cache]
        
        if not pending:
            return
        
        log.info(f"Geolocalizando {len(pending)} IPs...")
        
        for ip in pending:
            try:
                resp = requests.get(
                    f'http://ip-api.com/json/{ip}?fields=country,city,timezone,isp,status',
                    timeout=5,
                    headers={'User-Agent': 'xXACRVXx-Analytics/2.0'}
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('status') == 'success':
                        _geo_cache[ip] = {
                            'country': data.get('country', 'Desconocido'),
                            'city': data.get('city', 'Desconocido'),
                            'timezone': data.get('timezone', 'Desconocido'),
                            'isp': data.get('isp', 'Desconocido'),
                            'cached_at': time.time()
                        }
                    else:
                        _geo_cache[ip] = {
                            'country': 'IP Privada/VPN',
                            'city': 'Desconocido',
                            'timezone': 'Desconocido', 
                            'isp': 'Desconocido',
                            'cached_at': time.time()
                        }
                
                time.sleep(0.1)  # Rate limiting
                
            except Exception as e:
                log.debug(f"Error geolocalizando {ip}: {e}")
                _geo_cache[ip] = {
                    'country': 'Error',
                    'city': 'Error',
                    'timezone': 'Error',
                    'isp': 'Error',
                    'cached_at': time.time()
                }
        
        _update_geo_stats()

def _update_geo_stats():
    """Actualizar estadísticas geográficas."""
    try:
        # Limpiar stats geo actuales
        _analytics['geographic']['countries'].clear()
        _analytics['geographic']['cities'].clear()
        _analytics['geographic']['isps'].clear()
        _analytics['geographic']['timezones'].clear()
        
        # Procesar IPs externas
        for ip in _analytics['visitors']['external_ips']:
            if ip in _geo_cache:
                geo = _geo_cache[ip]
                _analytics['geographic']['countries'][geo['country']] += 1
                _analytics['geographic']['cities'][f"{geo['city']}, {geo['country']}"] += 1
                _analytics['geographic']['timezones'][geo['timezone']] += 1
                
                # Mapear ISP a nombre completo
                isp_name = geo['isp']
                for short, full in ISP_MAPPING.items():
                    if short.lower() in isp_name.lower():
                        isp_name = full
                        break
                _analytics['geographic']['isps'][isp_name] += 1
        
        # Agregar IPs locales
        local_count = len([ip for ip in _analytics['visitors']['unique_ips'] 
                          if ip.startswith(('127.', '192.168.', '10.', '172.'))])
        if local_count > 0:
            _analytics['geographic']['countries']['Red Local (LAN)'] = local_count
            _analytics['geographic']['cities']['Red Local, LAN'] = local_count
            
    except Exception as e:
        log.error(f"Error actualizando geo stats: {e}")

def _format_time_12h(hour_24: str) -> str:
    """Convertir hora 24h a formato 12h."""
    try:
        hour = int(hour_24)
        if hour == 0:
            return "12:00 AM"
        elif hour < 12:
            return f"{hour}:00 AM"
        elif hour == 12:
            return "12:00 PM"
        else:
            return f"{hour-12}:00 PM"
    except:
        return f"{hour_24}:00"

def _get_weekdays_data() -> Dict[str, int]:
    """Obtener datos de días de la semana ordenados correctamente."""
    try:
        weekdays_raw = _analytics['temporal'].get('weekdays', {})
        # Asegurar que todos los días estén presentes
        weekday_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        weekdays_ordered = {}
        
        for day in weekday_order:
            weekdays_ordered[day] = weekdays_raw.get(day, 0)
        
        return weekdays_ordered
    except Exception as e:
        log.error(f"Error obteniendo datos de weekdays: {e}")
        return {'Monday': 0, 'Tuesday': 0, 'Wednesday': 0, 'Thursday': 0, 'Friday': 0, 'Saturday': 0, 'Sunday': 0}

def _get_temporal_data(period: str, limit: int = None) -> List[Dict[str, Any]]:
    """Obtener datos temporales formateados."""
    now = datetime.now(timezone.utc)
    
    if period == 'hourly':
        # Últimas 24 horas
        data = []
        for i in range(24):
            hour_dt = now - timedelta(hours=i)
            key = hour_dt.strftime('%Y-%m-%d_%H')
            visits = _analytics['temporal']['hourly'].get(key, 0)
            data.append({
                'time': _format_time_12h(hour_dt.strftime('%H')),
                'visits': visits,
                'date': hour_dt.strftime('%Y-%m-%d')
            })
        return list(reversed(data))
    
    elif period == 'daily':
        # Últimos 30 días
        data = []
        for i in range(30):
            day_dt = now - timedelta(days=i)
            key = day_dt.strftime('%Y-%m-%d')
            visits = _analytics['temporal']['daily'].get(key, 0)
            data.append({
                'date': key,
                'visits': visits,
                'day_name': day_dt.strftime('%a')  # Lun, Mar, etc.
            })
        return list(reversed(data))
    
    elif period == 'monthly':
        # Últimos 12 meses
        data = []
        for i in range(12):
            month_dt = now - timedelta(days=i*30)
            key = month_dt.strftime('%Y-%m')
            visits = _analytics['temporal']['monthly'].get(key, 0)
            data.append({
                'month': key,
                'visits': visits,
                'month_name': month_dt.strftime('%b %Y')  # Ene 2024
            })
        return list(reversed(data))
    
    elif period == 'yearly':
        # Años con datos disponibles (máximo desde hace 1 año)
        data = []
        current_year = now.year
        # Solo mostrar años que tienen datos
        available_years = [year for year in _analytics['temporal']['yearly'].keys() if _analytics['temporal']['yearly'][year] > 0]
        available_years.sort()
        
        for year in available_years:
            visits = _analytics['temporal']['yearly'].get(year, 0)
            data.append({
                'year': year,
                'visits': visits
            })
        return data
    
    return []

def _get_top_items(category: str, limit: int = 10) -> List[Tuple[str, int]]:
    """Obtener top items ordenados correctamente."""
    if category == 'countries':
        items = _analytics['geographic']['countries']
    elif category == 'cities':
        items = _analytics['geographic']['cities']
    elif category == 'isps':
        items = _analytics['geographic']['isps']
    elif category == 'pages':
        items = _analytics['content']['pages']
    elif category == 'referrers':
        items = _analytics['content']['referrers']
    elif category == 'browsers':
        items = _analytics['technical']['browsers']
    elif category == 'os':
        items = _analytics['technical']['os']
    elif category == 'devices':
        items = _analytics['technical']['devices']
    elif category == 'resolutions':
        items = _analytics['technical'].get('resolutions', {})
    elif category == 'languages':
        items = _analytics['technical'].get('languages', {})
    elif category == 'connections':
        items = _analytics['technical'].get('connections', {})
    else:
        return []
    
    # Ordenar por visitas (descendente) y luego por nombre (ascendente)
    sorted_items = sorted(items.items(), key=lambda x: (-x[1], x[0]))
    return sorted_items[:limit]

def get_analytics_data(user_is_admin: bool = False) -> Dict[str, Any]:
    """API principal de analytics."""
    return get_unified_analytics_data(include_geo=True, user_is_admin=user_is_admin)

def get_unified_analytics_data(include_geo: bool = False, include_system: bool = False, 
                             force_geo: bool = False, user_is_admin: bool = False) -> Dict[str, Any]:
    """API unificada con todas las mejoras."""
    try:
        with _lock:
            # Geolocalizar solo si es admin
            if (include_geo or force_geo) and user_is_admin:
                _geolocate_ips()
            
            uptime = time.time() - _analytics['meta']['start_time']
            uptime_hours = max(uptime / 3600, 0.01)
            
            # Datos básicos
            data = {
                'total_visits': _analytics['meta']['total_visits'],
                'unique_visitors': len(_analytics['visitors']['unique_ips']),
                'avg_visits_per_hour': round(_analytics['meta']['total_visits'] / uptime_hours, 2),
                'uptime_hours': round(uptime_hours, 1),
                'last_save': datetime.fromtimestamp(_analytics['meta']['last_save']).strftime('%Y-%m-%d %H:%M:%S'),
                
                # Datos temporales mejorados
                'temporal': {
                    'hourly': _get_temporal_data('hourly'),
                    'daily': _get_temporal_data('daily'),
                    'monthly': _get_temporal_data('monthly'),
                    'yearly': _get_temporal_data('yearly'),
                    'weekdays': _get_weekdays_data()
                },
                
                # Top items ordenados
                'top_browsers': dict(_get_top_items('browsers')),
                'top_os': dict(_get_top_items('os')),
                'top_devices': dict(_get_top_items('devices')),
                'top_pages': dict(_get_top_items('pages')),
                'top_referrers': dict(_get_top_items('referrers')),
                
                # Estadísticas en tiempo real
                'realtime': _get_realtime_stats(),
                
                # Métricas calculadas
                'bounce_rate': _calculate_bounce_rate(),
                'return_visitor_rate': _calculate_return_rate(),
                'growth_rate': _calculate_growth_rate(),
                'avg_daily_visits': _get_avg_daily_visits(),
                
                # Info de bots
                'bots_detected': len(_analytics['technical']['bots']),
                'bot_visits': sum(_analytics['technical']['bots'].values()),
                
                # Métricas adicionales útiles
                'peak_hour_visits': _get_peak_hour_visits(),
                'most_popular_page': _get_most_popular_page(),
                'avg_pages_per_session': _calculate_avg_pages_per_session(),
                'new_vs_returning': _calculate_new_vs_returning(),
                'mobile_percentage': _calculate_mobile_percentage(),
                'top_referrer_domain': _get_top_referrer_domain(),
                
                # Nuevas métricas de cookies
                'top_resolutions': dict(_get_top_items('resolutions', 10)) if 'resolutions' in _analytics['technical'] else {},
                'top_languages': dict(_get_top_items('languages', 10)) if 'languages' in _analytics['technical'] else {},
                'top_connections': dict(_get_top_items('connections', 10)) if 'connections' in _analytics['technical'] else {},
                'unique_sessions': len(_analytics['visitors'].get('sessions', set())),
                
                # Nuevas métricas avanzadas
                'peak_traffic_day': _get_peak_traffic_day(),
                'busiest_hour_today': _get_busiest_hour_today(),
                'weekend_vs_weekday_ratio': _calculate_weekend_vs_weekday_ratio(),
                'avg_session_duration': _get_avg_session_duration(),
                
                # Métricas de engagement
                'engagement_metrics': {
                    'active_sessions': len(_analytics.get('engagement', {}).get('active_sessions', set())),
                    'bounce_sessions': len(_analytics.get('engagement', {}).get('bounce_sessions', set())),
                    'avg_session_pages': _calculate_avg_session_pages(),
                    'total_page_views': sum(_analytics['content']['pages'].values())
                },
                
                # Análisis de tráfico
                'traffic_analysis': {
                    'referrer_types': dict(_analytics.get('traffic', {}).get('referrer_types', {})),
                    'social_media': dict(_analytics.get('traffic', {}).get('social_media', {})),
                    'search_engines': dict(_analytics.get('traffic', {}).get('search_engines', {})),
                    'page_categories': dict(_analytics['content'].get('page_categories', {}))
                },
                
                # Métricas de usuarios
                'user_metrics': {
                    'unique_users': len(_analytics['visitors'].get('unique_users', set())),
                    'new_users': len(_analytics['visitors'].get('new_users', set())),
                    'returning_users': len(_analytics['visitors'].get('returning_users', set())),
                    'user_retention_rate': _calculate_user_retention_rate()
                }
            }
            
            # Datos geográficos (solo si se solicita)
            if include_geo:
                data.update({
                    'top_countries': dict(_get_top_items('countries', 15)),
                    'top_cities': dict(_get_top_items('cities', 15)),
                    'top_isps': dict(_get_top_items('isps', 10)),
                    'timezones': dict(sorted(_analytics['geographic']['timezones'].items(), 
                                           key=lambda x: (-x[1], x[0]))[:10]),
                    'pending_geolocate': len([ip for ip in _analytics['visitors']['external_ips'] if ip not in _geo_cache])
                })
            
            # Datos del sistema (solo si se solicita)
            if include_system:
                system_info = _get_system_info()
                # Agregar información adicional del sistema
                system_info.update({
                    'analytics_file_size': _get_analytics_file_size(),
                    'geo_cache_size': len(_geo_cache),
                    'data_retention_days': DATA_RETENTION_DAYS,
                    'save_interval_minutes': SAVE_INTERVAL // 60
                })
                data['system'] = system_info
            
            return data
            
    except Exception as e:
        log.error(f"Error obteniendo analytics: {e}")
        return {
            'total_visits': 0,
            'unique_visitors': 0,
            'error': str(e)
        }

def _calculate_user_retention_rate() -> float:
    """Calcular tasa de retención de usuarios."""
    try:
        total_users = len(_analytics['visitors'].get('unique_users', set()))
        returning_users = len(_analytics['visitors'].get('returning_users', set()))
        
        if total_users == 0:
            return 0.0
        
        return round((returning_users / total_users) * 100, 1)
    except:
        return 0.0

def _get_analytics_file_size() -> str:
    """Obtener tamaño del archivo de analytics."""
    try:
        if STATS_FILE.exists():
            size_bytes = STATS_FILE.stat().st_size
            if size_bytes < 1024:
                return f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.1f} KB"
            else:
                return f"{size_bytes / (1024 * 1024):.1f} MB"
        return "0 B"
    except:
        return "N/A"

def _get_realtime_stats() -> Dict[str, Any]:
    """Estadísticas en tiempo real."""
    try:
        now = datetime.now(timezone.utc)
        current_hour = now.strftime('%Y-%m-%d_%H')
        current_day = now.strftime('%Y-%m-%d')
        
        visits_this_hour = _analytics['temporal']['hourly'].get(current_hour, 0)
        visits_today = _analytics['temporal']['daily'].get(current_day, 0)
        
        # Hora más activa
        if _analytics['temporal']['hourly']:
            peak_hour = max(_analytics['temporal']['hourly'].items(), key=lambda x: x[1])
            peak_hour_formatted = _format_time_12h(peak_hour[0].split('_')[1])
        else:
            peak_hour_formatted = "Sin datos"
        
        # Estimación de usuarios online (basado en actividad reciente)
        recent_sessions = len(_analytics['visitors'].get('sessions', set()))
        online_estimate = max(1, min(visits_this_hour // 2, recent_sessions, 50)) if visits_this_hour > 0 else 0
        
        # Páginas por sesión más preciso
        total_page_views = sum(_analytics['content']['pages'].values())
        unique_sessions = len(_analytics['visitors'].get('sessions', set()))
        pages_per_session = round(total_page_views / max(unique_sessions, 1), 2)
        
        return {
            'visits_this_hour': visits_this_hour,
            'visits_today': visits_today,
            'online_estimate': online_estimate,
            'peak_hour': peak_hour_formatted,
            'current_time': now.strftime('%Y-%m-%d %I:%M:%S %p UTC'),
            'pages_per_session': pages_per_session,
            'active_sessions': len(_analytics.get('engagement', {}).get('active_sessions', set())),
            'bounce_sessions': len(_analytics.get('engagement', {}).get('bounce_sessions', set())),
            'avg_session_pages': _calculate_avg_session_pages()
        }
        
    except Exception as e:
        log.error(f"Error en realtime stats: {e}")
        return {'error': str(e)}

def _calculate_avg_session_pages() -> float:
    """Calcular promedio de páginas por sesión."""
    try:
        session_pages = _analytics.get('engagement', {}).get('session_pages', {})
        if not session_pages:
            return 0.0
        return round(sum(session_pages.values()) / len(session_pages), 2)
    except:
        return 0.0

def _get_peak_traffic_day() -> str:
    """Obtener el día con más tráfico."""
    try:
        if not _analytics['temporal']['daily']:
            return 'Sin datos'
        peak_day = max(_analytics['temporal']['daily'].items(), key=lambda x: x[1])
        return peak_day[0]  # Formato: YYYY-MM-DD
    except:
        return 'Sin datos'

def _get_busiest_hour_today() -> str:
    """Obtener la hora más activa de hoy."""
    try:
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        today_hours = {k: v for k, v in _analytics['temporal']['hourly'].items() if k.startswith(today)}
        
        if not today_hours:
            return '12:00 AM'
        
        busiest_hour = max(today_hours.items(), key=lambda x: x[1])
        hour = busiest_hour[0].split('_')[1]
        return _format_time_12h(hour)
    except:
        return '12:00 AM'

def _calculate_weekend_vs_weekday_ratio() -> float:
    """Calcular ratio de tráfico fin de semana vs días laborables."""
    try:
        weekdays_data = _analytics['temporal'].get('weekdays', {})
        if not weekdays_data:
            return 0.0
        
        weekend_visits = weekdays_data.get('Saturday', 0) + weekdays_data.get('Sunday', 0)
        weekday_visits = sum(weekdays_data.get(day, 0) for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'])
        
        if weekday_visits == 0:
            return 100.0 if weekend_visits > 0 else 0.0
        
        return round((weekend_visits / (weekend_visits + weekday_visits)) * 100, 1)
    except:
        return 0.0

def _get_avg_session_duration() -> float:
    """Calcular duración promedio de sesión (estimada)."""
    try:
        # Estimación basada en páginas por sesión y tiempo promedio por página
        avg_pages = _calculate_avg_session_pages()
        estimated_time_per_page = 2.5  # minutos estimados por página
        return round(avg_pages * estimated_time_per_page, 1)
    except:
        return 0.0

def _calculate_bounce_rate() -> float:
    """Calcular tasa de rebote.
    
    Bounce Rate = Porcentaje de sesiones de una sola página.
    Un 'rebote' ocurre cuando un visitante ve solo una página y se va.
    
    - 0-40%: Excelente
    - 41-55%: Promedio
    - 56-70%: Preocupante
    - 70%+: Problema serio
    
    Nota: Esta es una estimación basada en visitantes únicos vs visitas totales.
    """
    try:
        total = _analytics['meta']['total_visits']
        unique = len(_analytics['visitors']['unique_ips'])
        if total == 0:
            return 0.0
        return round((unique / total) * 100, 1)
    except:
        return 0.0

def _calculate_return_rate() -> float:
    """Calcular tasa de visitantes que regresan."""
    try:
        total = _analytics['meta']['total_visits']
        unique = len(_analytics['visitors']['unique_ips'])
        if total == 0 or unique == 0:
            return 0.0
        return_visits = max(0, total - unique)
        return round((return_visits / total) * 100, 1)
    except:
        return 0.0

def _get_peak_hour_visits() -> int:
    """Obtener número de visitas en la hora pico."""
    try:
        if not _analytics['temporal']['hourly']:
            return 0
        return max(_analytics['temporal']['hourly'].values())
    except:
        return 0

def _get_most_popular_page() -> str:
    """Obtener la página más popular."""
    try:
        if not _analytics['content']['pages']:
            return 'Sin datos'
        return max(_analytics['content']['pages'].items(), key=lambda x: x[1])[0]
    except:
        return 'Sin datos'

def _calculate_avg_pages_per_session() -> float:
    """Calcular promedio de páginas por sesión."""
    try:
        total_page_views = sum(_analytics['content']['pages'].values())
        unique_visitors = len(_analytics['visitors']['unique_ips'])
        if unique_visitors == 0:
            return 0.0
        return round(total_page_views / unique_visitors, 2)
    except:
        return 0.0

def _calculate_new_vs_returning() -> Dict[str, float]:
    """Calcular porcentaje de visitantes nuevos vs que regresan."""
    try:
        total = _analytics['meta']['total_visits']
        unique = len(_analytics['visitors']['unique_ips'])
        if total == 0:
            return {'new': 0.0, 'returning': 0.0}
        
        new_percentage = round((unique / total) * 100, 1)
        returning_percentage = round(100 - new_percentage, 1)
        
        return {'new': new_percentage, 'returning': returning_percentage}
    except:
        return {'new': 0.0, 'returning': 0.0}

def _calculate_mobile_percentage() -> float:
    """Calcular porcentaje de tráfico móvil."""
    try:
        total_devices = sum(_analytics['technical']['devices'].values())
        if total_devices == 0:
            return 0.0
        
        mobile_visits = _analytics['technical']['devices'].get('Móvil', 0)
        tablet_visits = _analytics['technical']['devices'].get('Tablet', 0)
        mobile_total = mobile_visits + tablet_visits
        
        return round((mobile_total / total_devices) * 100, 1)
    except:
        return 0.0

def _get_top_referrer_domain() -> str:
    """Obtener el dominio referrer principal."""
    try:
        if not _analytics['content']['referrers']:
            return 'Directo'
        
        top_referrer = max(_analytics['content']['referrers'].items(), key=lambda x: x[1])[0]
        
        # Extraer dominio de la URL
        if 'http' in top_referrer:
            from urllib.parse import urlparse
            domain = urlparse(top_referrer).netloc
            return domain if domain else top_referrer
        
        return top_referrer
    except:
        return 'Sin datos'

def _calculate_growth_rate() -> float:
    """Calcular tasa de crecimiento diario."""
    try:
        now = datetime.now(timezone.utc)
        today = now.strftime('%Y-%m-%d')
        yesterday = (now - timedelta(days=1)).strftime('%Y-%m-%d')
        
        today_visits = _analytics['temporal']['daily'].get(today, 0)
        yesterday_visits = _analytics['temporal']['daily'].get(yesterday, 0)
        
        if yesterday_visits == 0:
            return 100.0 if today_visits > 0 else 0.0
        
        return round(((today_visits - yesterday_visits) / yesterday_visits) * 100, 1)
    except:
        return 0.0

def _get_avg_daily_visits() -> float:
    """Promedio de visitas diarias."""
    try:
        daily_visits = list(_analytics['temporal']['daily'].values())
        if not daily_visits:
            return 0.0
        return round(sum(daily_visits) / len(daily_visits), 1)
    except:
        return 0.0

def _get_system_info() -> Dict[str, Any]:
    """Info del sistema."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            'cpu_percent': round(psutil.cpu_percent(interval=0.1), 1),
            'memory_percent': round(mem.percent, 1),
            'disk_percent': round((disk.used / disk.total) * 100, 1),
            'process_count': len(psutil.pids())
        }
    except ImportError:
        return {'error': 'psutil no disponible'}
    except Exception as e:
        return {'error': str(e)}

def get_real_time_stats() -> Dict[str, Any]:
    """Alias para compatibilidad."""
    return _get_realtime_stats()

def reset_analytics(user_is_admin: bool = False) -> bool:
    """Resetear analytics (solo admin)."""
    if not user_is_admin:
        log.warning("Intento de reset sin permisos de admin")
        return False
    
    try:
        with _lock:
            global _analytics, _geo_cache
            
            # Backup antes de resetear
            if _analytics['meta']['total_visits'] > 0:
                backup_name = f"reset_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                _ensure_dirs()
                with open(BACKUP_DIR / backup_name, 'w', encoding='utf-8') as f:
                    json.dump(_serialize_data(), f, indent=2, ensure_ascii=False)
            
            # Resetear estructura
            _analytics = {
                'meta': {
                    'version': '2.1',
                    'start_time': time.time(),
                    'last_save': time.time(),
                    'total_visits': 0
                },
                'visitors': {
                    'unique_ips': set(),
                    'external_ips': [],
                    'sessions': set(),
                    'unique_users': set(),
                    'new_users': set(),
                    'returning_users': set()
                },
                'temporal': {
                    'hourly': defaultdict(int),
                    'daily': defaultdict(int),
                    'monthly': defaultdict(int),
                    'yearly': defaultdict(int),
                    'weekdays': defaultdict(int)
                },
                'geographic': {
                    'countries': defaultdict(int),
                    'cities': defaultdict(int),
                    'isps': defaultdict(int),
                    'timezones': defaultdict(int)
                },
                'technical': {
                    'browsers': defaultdict(int),
                    'os': defaultdict(int),
                    'devices': defaultdict(int),
                    'bots': defaultdict(int),
                    'resolutions': defaultdict(int),
                    'languages': defaultdict(int),
                    'connections': defaultdict(int)
                },
                'content': {
                    'pages': defaultdict(int),
                    'referrers': defaultdict(int),
                    'page_categories': defaultdict(int)
                },
                'engagement': {
                    'session_pages': defaultdict(int),
                    'session_duration': defaultdict(float),
                    'bounce_sessions': set(),
                    'active_sessions': set()
                },
                'traffic': {
                    'referrer_types': defaultdict(int),
                    'social_media': defaultdict(int),
                    'search_engines': defaultdict(int)
                }
            }
            
            _geo_cache.clear()
            
            save_analytics_data()
            
            log.info("Analytics reseteados correctamente")
            return True
            
    except Exception as e:
        log.error(f"Error reseteando analytics: {e}")
        return False

def export_analytics(user_is_admin: bool = False) -> Optional[str]:
    """Exportar analytics (solo admin)."""
    if not user_is_admin:
        log.warning("Intento de export sin permisos de admin")
        return None
    
    try:
        with _lock:
            _ensure_dirs()
            
            # Datos completos para export
            export_data = {
                'export_info': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'version': '2.1',
                    'total_visits': _analytics['meta']['total_visits']
                },
                'analytics_data': _serialize_data(),
                'geo_cache': _geo_cache
            }
            
            filename = f"analytics_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = Path('exports') / filename
            filepath.parent.mkdir(exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            log.info(f"Analytics exportados: {filepath}")
            return str(filepath)
            
    except Exception as e:
        log.error(f"Error exportando analytics: {e}")
        return None

def import_analytics(filepath: str, user_is_admin: bool = False) -> bool:
    """Importar analytics (solo admin)."""
    if not user_is_admin:
        log.warning("Intento de import sin permisos de admin")
        return False
    
    try:
        with _lock:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'analytics_data' not in data:
                log.error("Formato de archivo inválido")
                return False
            
            # Backup antes de importar
            backup_name = f"import_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            _ensure_dirs()
            with open(BACKUP_DIR / backup_name, 'w', encoding='utf-8') as f:
                json.dump(_serialize_data(), f, indent=2, ensure_ascii=False)
            
            # Importar datos
            _deserialize_data(data['analytics_data'])
            
            if 'geo_cache' in data:
                global _geo_cache
                _geo_cache = data['geo_cache']
            
            save_analytics_data()
            log.info(f"Analytics importados desde: {filepath}")
            return True
            
    except Exception as e:
        log.error(f"Error importando analytics: {e}")
        return False

def get_comprehensive_report() -> Dict[str, Any]:
    """Generar reporte completo de analytics para administradores."""
    try:
        with _lock:
            data = get_unified_analytics_data(include_geo=True, include_system=True, user_is_admin=True)
            
            # Agregar análisis adicionales
            report = {
                'summary': {
                    'total_visits': data['total_visits'],
                    'unique_visitors': data['unique_visitors'],
                    'bounce_rate': data['bounce_rate'],
                    'avg_session_duration': data['avg_session_duration'],
                    'mobile_percentage': data['mobile_percentage']
                },
                'performance': {
                    'peak_traffic_day': data['peak_traffic_day'],
                    'busiest_hour_today': data['busiest_hour_today'],
                    'growth_rate': data['growth_rate'],
                    'weekend_vs_weekday_ratio': data['weekend_vs_weekday_ratio']
                },
                'content_analysis': {
                    'most_popular_page': data['most_popular_page'],
                    'top_pages': data['top_pages'],
                    'page_categories': data['traffic_analysis']['page_categories'],
                    'avg_pages_per_session': data['avg_pages_per_session']
                },
                'audience': {
                    'top_countries': data.get('top_countries', {}),
                    'top_browsers': data['top_browsers'],
                    'top_devices': data['top_devices'],
                    'user_retention_rate': data['user_metrics']['user_retention_rate']
                },
                'traffic_sources': {
                    'referrer_types': data['traffic_analysis']['referrer_types'],
                    'social_media': data['traffic_analysis']['social_media'],
                    'search_engines': data['traffic_analysis']['search_engines'],
                    'top_referrer_domain': data['top_referrer_domain']
                },
                'technical': {
                    'bots_detected': data['bots_detected'],
                    'top_resolutions': data['top_resolutions'],
                    'top_languages': data['top_languages'],
                    'system_info': data.get('system', {})
                },
                'temporal_patterns': {
                    'hourly_distribution': data['temporal']['hourly'][-24:] if len(data['temporal']['hourly']) >= 24 else data['temporal']['hourly'],
                    'daily_trend': data['temporal']['daily'][-30:] if len(data['temporal']['daily']) >= 30 else data['temporal']['daily'],
                    'weekday_distribution': data['temporal']['weekdays']
                }
            }
            
            return report
            
    except Exception as e:
        log.error(f"Error generando reporte completo: {e}")
        return {'error': str(e)}

def force_save_analytics():
    """Forzar guardado inmediato de analytics."""
    try:
        save_analytics_data()
        log.info("Analytics guardados forzadamente")
        return True
    except Exception as e:
        log.error(f"Error en guardado forzado: {e}")
        return False

def get_analytics_status():
    """Obtener estado actual de analytics."""
    return {
        'total_visits': _analytics['meta']['total_visits'],
        'unique_visitors': len(_analytics['visitors']['unique_ips']),
        'last_save': _analytics['meta']['last_save'],
        'data_file_exists': STATS_FILE.exists(),
        'geo_cache_size': len(_geo_cache)
    }

# Inicialización automática al importar el módulo
try:
    _ensure_dirs()
    load_analytics_data()
    
    # Verificar que los datos se cargaron correctamente
    total_visits = _analytics['meta']['total_visits']
    unique_visitors = len(_analytics['visitors']['unique_ips'])
    
    log.info(f"Módulo Analytics 2.1 inicializado - {total_visits} visitas, {unique_visitors} visitantes únicos cargados")
    
    # Si no hay datos pero el archivo existe, puede haber un problema de deserialización
    if total_visits == 0 and STATS_FILE.exists():
        log.warning("Archivo de analytics existe pero no se cargaron datos - posible problema de deserialización")
        
except Exception as e:
    log.error(f"Error inicializando analytics: {e}")