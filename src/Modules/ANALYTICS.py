#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Analíticas para xXACRVXx Web
=====================================
Sistema de métricas y estadísticas de visitas.
"""

import os
import json
import time
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Any

log = logging.getLogger("ANALYTICS")

# Variables globales para métricas
_visit_stats = {
    'total_visits': 0,
    'unique_ips': set(),
    'ip_list': [],  # Lista de IPs para geolocalizar después
    'countries': defaultdict(int),
    'hourly_visits': defaultdict(int),
    'daily_visits': defaultdict(int),
    'user_agents': defaultdict(int),
    'pages': defaultdict(int),
    'referrers': defaultdict(int),
    'start_time': time.time()
}

# Cache para datos de geolocalización
_geo_cache = {}
_geo_cache_time = 0

def record_visit(ip: str, user_agent: str = '', page: str = '', referrer: str = ''):
    """Registrar una visita (SIN geolocalización para mejor rendimiento)."""
    try:
        _visit_stats['total_visits'] += 1
        _visit_stats['unique_ips'].add(ip)
        
        # Almacenar IP para geolocalizar después SOLO si es externa
        if not ip.startswith(('127.', '192.168.', '10.')) and ip not in _visit_stats['ip_list']:
            _visit_stats['ip_list'].append(ip)
        
        # Registrar por hora
        current_hour = datetime.now().strftime('%H')
        _visit_stats['hourly_visits'][current_hour] += 1
        
        # Registrar por día
        current_day = datetime.now().strftime('%Y-%m-%d')
        _visit_stats['daily_visits'][current_day] += 1
        
        # Registrar por mes
        current_month = datetime.now().strftime('%Y-%m')
        _visit_stats.setdefault('monthly_visits', defaultdict(int))[current_month] += 1
        
        # Detectar dispositivo y SO
        if user_agent:
            ua_lower = user_agent.lower()
            
            # Navegadores
            if 'chrome' in ua_lower and 'edg' not in ua_lower:
                browser = 'Chrome'
            elif 'firefox' in ua_lower:
                browser = 'Firefox'
            elif 'safari' in ua_lower and 'chrome' not in ua_lower:
                browser = 'Safari'
            elif 'edg' in ua_lower:
                browser = 'Edge'
            else:
                browser = 'Otro'
            _visit_stats['user_agents'][browser] += 1
            
            # Sistemas operativos
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
            _visit_stats.setdefault('operating_systems', defaultdict(int))[os_name] += 1
            
            # Dispositivos
            if 'mobile' in ua_lower or 'android' in ua_lower or 'iphone' in ua_lower:
                device = 'Móvil'
            elif 'tablet' in ua_lower or 'ipad' in ua_lower:
                device = 'Tablet'
            else:
                device = 'Escritorio'
            _visit_stats.setdefault('devices', defaultdict(int))[device] += 1
            
            # Bots
            if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']):
                _visit_stats.setdefault('bots', defaultdict(int))[user_agent[:50]] += 1
        
        # Página visitada
        if page:
            _visit_stats['pages'][page] += 1
        
        # Referrer
        if referrer and referrer != '-':
            _visit_stats['referrers'][referrer] += 1
            
    except Exception as e:
        log.error(f"Error registrando visita: {e}")

def _geolocate_ips_for_admin():
    """Geolocalizar IPs SOLO cuando se accede al monitor de admin."""
    global _geo_cache, _geo_cache_time
    
    try:
        try:
            import requests
        except ImportError:
            log.warning("Módulo requests no disponible para geolocalización")
            return
        
        # Procesar todas las IPs pendientes
        for ip in _visit_stats['ip_list']:
            if ip in _geo_cache:
                continue
                
            try:
                response = requests.get(
                    f'http://ip-api.com/json/{ip}?fields=country,city,timezone,isp', 
                    timeout=3
                )
                if response.status_code == 200:
                    data = response.json()
                    _geo_cache[ip] = {
                        'country': data.get('country', 'Desconocido'),
                        'city': data.get('city', 'Desconocido'),
                        'timezone': data.get('timezone', 'Desconocido'),
                        'isp': data.get('isp', 'Desconocido')
                    }
                else:
                    _geo_cache[ip] = {
                        'country': 'Desconocido',
                        'city': 'Desconocido', 
                        'timezone': 'Desconocido',
                        'isp': 'Desconocido'
                    }
                # Pausa para no saturar la API
                time.sleep(0.1)
            except:
                _geo_cache[ip] = {
                    'country': 'Error',
                    'city': 'Error',
                    'timezone': 'Error', 
                    'isp': 'Error'
                }
        
        # Actualizar estadísticas con datos geolocalizados
        _visit_stats['countries'].clear()
        _visit_stats.setdefault('cities', defaultdict(int)).clear()
        _visit_stats.setdefault('timezones', defaultdict(int)).clear()
        _visit_stats.setdefault('isps', defaultdict(int)).clear()
        
        for ip in _visit_stats['ip_list']:
            if ip in _geo_cache:
                geo_data = _geo_cache[ip]
                _visit_stats['countries'][geo_data['country']] += 1
                _visit_stats['cities'][f"{geo_data['city']}, {geo_data['country']}"] += 1
                _visit_stats['timezones'][geo_data['timezone']] += 1
                _visit_stats['isps'][geo_data['isp']] += 1
        
        # Agregar IPs locales
        local_ips = len([ip for ip in _visit_stats['unique_ips'] 
                        if ip.startswith(('127.', '192.168.', '10.'))])
        if local_ips > 0:
            _visit_stats['countries']['Local'] = local_ips
            
        _geo_cache_time = time.time()
        log.info(f"Geolocalización completada: {len(_geo_cache)} IPs procesadas")
        
    except Exception as e:
        log.error(f"Error geolocalizando IPs: {e}")

def get_analytics_data() -> Dict[str, Any]:
    """Obtener datos de analíticas (mantener compatibilidad)."""
    return get_unified_analytics_data(include_geo=True, include_system=False)

def get_unified_analytics_data(include_geo: bool = False, include_system: bool = False, force_geo: bool = False) -> Dict[str, Any]:
    """API unificada de analytics con opciones configurables."""
    try:
        # Geolocalizar SOLO si se solicita explícitamente
        if include_geo or force_geo:
            _geolocate_ips_for_admin()
        
        uptime_seconds = time.time() - _visit_stats['start_time']
        uptime_hours = uptime_seconds / 3600
        
        # Datos básicos siempre incluidos
        data = {
            'total_visits': _visit_stats['total_visits'],
            'unique_visitors': len(_visit_stats['unique_ips']),
            'avg_visits_per_hour': round(_visit_stats['total_visits'] / max(uptime_hours, 1), 2),
            'uptime_hours': round(uptime_hours, 1),
            'pending_geolocate': len(_visit_stats['ip_list']) - len(_geo_cache),
            
            # Estadísticas en tiempo real
            'realtime': get_real_time_stats(),
            
            # Navegadores y dispositivos
            'browsers': dict(_visit_stats['user_agents']),
            'operating_systems': dict(_visit_stats.get('operating_systems', {})),
            'devices': dict(_visit_stats.get('devices', {})),
            
            # Páginas y referrers
            'top_pages': dict(Counter(_visit_stats['pages']).most_common(10)),
            'top_referrers': dict(Counter(_visit_stats['referrers']).most_common(10)),
            
            # Datos temporales
            'hourly_visits': _get_hourly_data(),
            'daily_visits': _get_daily_data(),
            'monthly_visits': _get_monthly_data(),
            
            # Bots y métricas avanzadas
            'bots_detected': len(_visit_stats.get('bots', {})),
            'bounce_rate': round((len(_visit_stats['unique_ips']) / max(_visit_stats['total_visits'], 1)) * 100, 1),
            'avg_session_duration': round(uptime_hours * 60 / max(len(_visit_stats['unique_ips']), 1), 1),
            
            # Información adicional útil
            'visits_per_unique_ip': round(_visit_stats['total_visits'] / max(len(_visit_stats['unique_ips']), 1), 2),
            'most_active_hour': max(_visit_stats['hourly_visits'].items(), key=lambda x: x[1], default=('00', 0)),
            'total_unique_pages': len(_visit_stats['pages']),
            'total_referrer_sources': len(_visit_stats['referrers']),
            
            # Métricas de crecimiento
            'growth_rate': _calculate_growth_rate(),
            'avg_daily_visits': _get_avg_daily_visits(),
            'return_visitor_rate': _calculate_return_rate()
        }
        
        # Datos geográficos (solo si se solicita)
        if include_geo:
            # Si no hay datos geográficos, mostrar IPs locales/pendientes
            countries = dict(Counter(_visit_stats['countries']).most_common(15))
            if not countries and _visit_stats['ip_list']:
                countries = {'Pendiente geolocalizar': len(_visit_stats['ip_list'])}
            
            local_count = len([ip for ip in _visit_stats['unique_ips'] if ip.startswith(('127.', '192.168.', '10.'))])
            if local_count > 0:
                countries['Local/Privada'] = local_count
            
            data.update({
                'top_countries': countries,
                'top_cities': dict(Counter(_visit_stats.get('cities', {})).most_common(15)),
                'top_isps': dict(Counter(_visit_stats.get('isps', {})).most_common(10)),
                'timezones': dict(Counter(_visit_stats.get('timezones', {})).most_common(10))
            })
        
        # Datos del sistema (solo si se solicita)
        if include_system:
            try:
                import psutil
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                data['system'] = {
                    'cpu_percent': round(psutil.cpu_percent(interval=0.1), 1),
                    'memory_percent': round(mem.percent, 1),
                    'memory_total_gb': round(mem.total / (1024**3), 1),
                    'memory_used_gb': round(mem.used / (1024**3), 1),
                    'disk_percent': round((disk.used / disk.total) * 100, 1),
                    'disk_total_gb': round(disk.total / (1024**3), 1),
                    'disk_free_gb': round(disk.free / (1024**3), 1),
                    'network_connections': len(psutil.net_connections()),
                    'process_count': len(psutil.pids()),
                    'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
                    'load_avg': list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else [0, 0, 0]
                }
            except ImportError:
                log.debug("Módulo psutil no disponible")
                data['system'] = {'error': 'psutil no instalado'}
            except Exception as e:
                log.debug(f"Error obteniendo datos del sistema: {e}")
                data['system'] = {'error': 'No disponible'}
        
        return data
        
    except Exception as e:
        log.error(f"Error obteniendo analytics unificados: {e}")
        return {
            'total_visits': 0,
            'unique_visitors': 0,
            'error': str(e)
        }

def _get_hourly_data():
    """Obtener datos por hora para las últimas 24h."""
    hourly_data = []
    for hour in range(24):
        hour_str = f"{hour:02d}"
        visits = _visit_stats['hourly_visits'].get(hour_str, 0)
        hourly_data.append({'hour': hour_str, 'visits': visits})
    return hourly_data

def _get_daily_data():
    """Obtener datos por día para los últimos 7 días."""
    daily_data = []
    for i in range(7):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        visits = _visit_stats['daily_visits'].get(date, 0)
        daily_data.append({'date': date, 'visits': visits})
    daily_data.reverse()
    return daily_data

def _get_monthly_data():
    """Obtener datos por mes para los últimos 6 meses."""
    monthly_data = []
    for i in range(6):
        date = (datetime.now() - timedelta(days=i*30)).strftime('%Y-%m')
        visits = _visit_stats.get('monthly_visits', {}).get(date, 0)
        month_name = datetime.strptime(date, '%Y-%m').strftime('%b %Y')
        monthly_data.append({'month': month_name, 'visits': visits})
    monthly_data.reverse()
    return monthly_data

def _calculate_growth_rate():
    """Calcular tasa de crecimiento diario."""
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        
        today_visits = _visit_stats['daily_visits'].get(today, 0)
        yesterday_visits = _visit_stats['daily_visits'].get(yesterday, 0)
        
        if yesterday_visits == 0:
            return 0 if today_visits == 0 else 100
        
        return round(((today_visits - yesterday_visits) / yesterday_visits) * 100, 1)
    except:
        return 0

def _get_avg_daily_visits():
    """Calcular promedio de visitas diarias."""
    try:
        daily_visits = list(_visit_stats['daily_visits'].values())
        if not daily_visits:
            return 0
        return round(sum(daily_visits) / len(daily_visits), 1)
    except:
        return 0

def _calculate_return_rate():
    """Calcular tasa estimada de visitantes que regresan."""
    try:
        total_visits = _visit_stats['total_visits']
        unique_visitors = len(_visit_stats['unique_ips'])
        
        if unique_visitors == 0:
            return 0
        
        return_visits = total_visits - unique_visitors
        return round((return_visits / total_visits) * 100, 1) if total_visits > 0 else 0
    except:
        return 0

def get_real_time_stats() -> Dict[str, Any]:
    """Obtener estadísticas en tiempo real."""
    try:
        now = datetime.now()
        current_hour = now.strftime('%H')
        current_day = now.strftime('%Y-%m-%d')
        
        visits_last_hour = _visit_stats['hourly_visits'].get(current_hour, 0)
        visits_today = _visit_stats['daily_visits'].get(current_day, 0)
        top_referrers = dict(Counter(_visit_stats['referrers']).most_common(5))
        peak_hour_data = max(_visit_stats['hourly_visits'].items(), key=lambda x: x[1], default=('00', 0))
        
        return {
            'visits_last_hour': visits_last_hour,
            'visits_today': visits_today,
            'online_now': max(1, min(visits_last_hour // 2, 20)) if visits_last_hour > 0 else 0,
            'peak_hour': peak_hour_data,
            'top_referrers': top_referrers,
            'pages_per_session': round(_visit_stats['total_visits'] / max(len(_visit_stats['unique_ips']), 1), 2)
        }
        
    except Exception as e:
        log.error(f"Error obteniendo stats en tiempo real: {e}")
        return {
            'visits_last_hour': 0,
            'visits_today': 0,
            'online_now': 0,
            'peak_hour': ('00', 0)
        }

def reset_analytics():
    """Resetear estadísticas."""
    global _visit_stats, _geo_cache, _geo_cache_time
    _visit_stats = {
        'total_visits': 0,
        'unique_ips': set(),
        'ip_list': [],
        'countries': defaultdict(int),
        'hourly_visits': defaultdict(int),
        'daily_visits': defaultdict(int),
        'user_agents': defaultdict(int),
        'pages': defaultdict(int),
        'referrers': defaultdict(int),
        'start_time': time.time()
    }
    _geo_cache = {}
    _geo_cache_time = 0
    log.info("Estadísticas de analíticas reseteadas")

def export_analytics() -> str:
    """Exportar analíticas a JSON."""
    try:
        # Forzar geolocalización completa antes de exportar
        _geolocate_ips_for_admin()
        
        data = get_analytics_data()
        data['unique_ips_list'] = list(_visit_stats['unique_ips'])
        
        filename = f"analytics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(os.getcwd(), 'exports', filename)
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filepath
        
    except Exception as e:
        log.error(f"Error exportando analíticas: {e}")
        return None