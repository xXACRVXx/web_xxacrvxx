import os
import time
import datetime
import tempfile
import logging
from Modules import USERPG, BLOGPG, CONFIG

log = logging.getLogger("ADMIN")

# Cache global para posts
_posts_cache = None
_posts_cache_time = 0

# Contador global de intentos fallidos
_failed_login_attempts = 0
_failed_login_hour = datetime.datetime.now().strftime("%Y-%m-%d-%H")

def increment_failed_login():
    global _failed_login_attempts, _failed_login_hour
    current_hour = datetime.datetime.now().strftime("%Y-%m-%d-%H")
    
    # Reset cada hora
    if _failed_login_hour != current_hour:
        _failed_login_attempts = 0
        _failed_login_hour = current_hour
    
    _failed_login_attempts += 1
    log.warning(f"Intento de login fallido #{_failed_login_attempts} en la hora {current_hour}")

def get_failed_login_count():
    global _failed_login_attempts, _failed_login_hour
    current_hour = datetime.datetime.now().strftime("%Y-%m-%d-%H")
    
    # Reset cada hora
    if _failed_login_hour != current_hour:
        _failed_login_attempts = 0
        _failed_login_hour = current_hour
    
    return _failed_login_attempts

def get_cached_posts():
    global _posts_cache, _posts_cache_time
    current_time = time.time()
    
    # Cache más largo para evitar cambios constantes en las estadísticas
    if _posts_cache is None or (current_time - _posts_cache_time) > 300:  # 5 minutos
        try:
            posts = BLOGPG.GET_BL('all')
            _posts_cache = posts if posts is not None else []
            _posts_cache_time = current_time
            log.debug(f"Cache de posts actualizado: {len(_posts_cache)} posts")
        except Exception as e:
            log.error(f"Error actualizando cache de posts: {e}")
            if _posts_cache is None:
                _posts_cache = []
    
    return _posts_cache

def get_system_stats():
    """Obtener estadísticas básicas del sistema"""
    try:
        all_posts = get_cached_posts()
        enhanced_stats = CONFIG.get_enhanced_system_stats()
        
        # Redondear valores para evitar decimales innecesarios
        disk_usage = round(enhanced_stats.get('disk_usage', 0), 1)
        memory_usage = round(enhanced_stats.get('memory_usage', 0), 1)
        
        return {
            'users': len(USERPG.GET_ALL_USERS() or []),
            'posts': len(all_posts),
            'files': CONFIG.count_user_files(),
            'uptime': CONFIG.get_uptime(),
            'disk_usage': disk_usage,
            'memory_usage': memory_usage,
            'os_name': enhanced_stats.get('os_name', 'Desconocido'),
            'python_version': enhanced_stats.get('python_version', 'Desconocido'),
            'hostname': enhanced_stats.get('hostname', 'Desconocido'),
            'local_ip': enhanced_stats.get('local_ip', 'No disponible'),
            'external_ip': enhanced_stats.get('external_ip', 'No disponible'),
            'process_memory': round(enhanced_stats.get('process_memory', 0), 1),
            'process_cpu': round(enhanced_stats.get('process_cpu', 0), 1),
            'threads_count': enhanced_stats.get('threads_count', 0),
            'network_connections': enhanced_stats.get('network_connections', 0)
        }
    except Exception as e:
        log.error(f"Error obteniendo estadísticas: {e}")
        return {
            'users': 0, 'posts': 0, 'files': 0, 'uptime': '0h 0m', 
            'disk_usage': 0, 'memory_usage': 0, 'os_name': 'Error',
            'python_version': 'Error', 'hostname': 'Error', 
            'local_ip': 'Error', 'external_ip': 'Error',
            'process_memory': 0, 'process_cpu': 0, 'threads_count': 0,
            'network_connections': 0
        }

def get_active_users():
    """Obtener usuarios activos hoy"""
    try:
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        all_users = USERPG.GET_ALL_USERS() or []
        active_users = []
        
        for user in all_users:
            last_activity = user.get('extra', '')
            if last_activity and today in last_activity:
                active_users.append({
                    'username': user['username'],
                    'last_seen': last_activity[:16] if len(last_activity) >= 16 else last_activity,
                    'email': user.get('email', ''),
                    'verified': user.get('email_confirm') == 'true'
                })
        
        # Ordenar por última actividad
        active_users.sort(key=lambda x: x['last_seen'], reverse=True)
        return active_users[:15]
    except Exception as e:
        log.error(f"Error obteniendo usuarios activos: {e}")
        return []

def get_recent_files(upload_folder):
    """Obtener archivos recientes"""
    try:
        recent_files = []
        
        if os.path.exists(upload_folder):
            for user_dir in os.listdir(upload_folder):
                user_path = os.path.join(upload_folder, user_dir)
                if os.path.isdir(user_path) and user_dir.isdigit():
                    try:
                        user_data = USERPG.GET_USER('id', int(user_dir))
                        username = user_data['username'] if user_data and isinstance(user_data, dict) else f'Usuario {user_dir}'
                        
                        # Recorrer recursivamente todos los archivos
                        for root, dirs, files in os.walk(user_path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    mtime = os.path.getmtime(file_path)
                                    recent_files.append({
                                        'name': file,
                                        'user': username,
                                        'time': mtime,
                                        'path': os.path.relpath(file_path, user_path)
                                    })
                                except:
                                    continue
                    except Exception as e:
                        log.debug(f"Error procesando directorio {user_dir}: {e}")
                        continue
        
        recent_files.sort(key=lambda x: x['time'], reverse=True)
        return recent_files[:15]
    except Exception as e:
        log.error(f"Error obteniendo archivos recientes: {e}")
        return []

def get_popular_posts():
    """Obtener posts más populares"""
    try:
        posts = get_cached_posts()
        popular_posts = []
        
        for post in posts:
            creat_id = post.get('creat_id')
            author_name = 'Desconocido'
            
            # creat_id puede ser username o ID numérico
            if creat_id:
                if str(creat_id).isdigit():
                    author_data = USERPG.GET_USER('id', int(creat_id))
                    author_name = author_data['username'] if author_data and isinstance(author_data, dict) else f'Usuario {creat_id}'
                else:
                    author_name = str(creat_id)
            
            popular_posts.append({
                'title': post.get('title', 'Sin título'),
                'views': post.get('count_view', 0),
                'author': author_name,
                'date': post.get('time', '')[:10] if post.get('time') else '',
                'comments': 0  # Se calculará después si es necesario
            })
        
        popular_posts.sort(key=lambda x: x['views'], reverse=True)
        return popular_posts[:10]
    except Exception as e:
        log.error(f"Error obteniendo posts populares: {e}")
        return []

def cleanup_temp_files():
    """Limpiar archivos temporales y cache"""
    try:
        import tempfile
        temp_files = 0
        
        # Limpiar archivos temporales del sistema
        try:
            temp_dir = tempfile.gettempdir()
            for file in os.listdir(temp_dir):
                if any(file.startswith(prefix) for prefix in ['tmp', 'flask_', 'werkzeug_']) or file.endswith('.tmp'):
                    try:
                        file_path = os.path.join(temp_dir, file)
                        if os.path.isfile(file_path) and time.time() - os.path.getmtime(file_path) > 3600:  # 1 hora
                            os.remove(file_path)
                            temp_files += 1
                    except:
                        continue
        except:
            pass
        
        # Limpiar logs antiguos
        try:
            logs_dir = os.path.join(CONFIG.SYSTEM_PATH, 'logs')
            if os.path.exists(logs_dir):
                current_time = time.time()
                for log_file in os.listdir(logs_dir):
                    if log_file.endswith('.log'):
                        log_path = os.path.join(logs_dir, log_file)
                        # Eliminar logs de más de 7 días
                        if current_time - os.path.getmtime(log_path) > 7 * 24 * 3600:
                            try:
                                os.remove(log_path)
                                temp_files += 1
                            except:
                                continue
        except:
            pass
        
        # Limpiar cache de Python
        try:
            import shutil
            pycache_dirs = []
            for root, dirs, files in os.walk(CONFIG.SYSTEM_PATH):
                if '__pycache__' in dirs:
                    pycache_dirs.append(os.path.join(root, '__pycache__'))
            
            for pycache_dir in pycache_dirs:
                try:
                    shutil.rmtree(pycache_dir)
                    temp_files += 1
                except:
                    continue
        except:
            pass
        
        # Limpiar archivos .pyc
        try:
            for root, dirs, files in os.walk(CONFIG.SYSTEM_PATH):
                for file in files:
                    if file.endswith('.pyc'):
                        try:
                            os.remove(os.path.join(root, file))
                            temp_files += 1
                        except:
                            continue
        except:
            pass
        
        log.info(f"Limpieza completada: {temp_files} archivos eliminados")
        return temp_files
        
    except Exception as e:
        log.error(f"Error limpiando archivos temporales: {e}")
        return 0

def get_security_info():
    """Obtener información de seguridad"""
    try:
        users = USERPG.GET_ALL_USERS() or []
        verified_count = len([u for u in users if u.get('email_confirm') == 'true'])
        verified_percentage = int((verified_count / len(users)) * 100) if users else 0
        
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        active_sessions = len([u for u in users if u.get('extra') and today in u.get('extra', '')])
        
        # Buscar último acceso de admin
        admin_users = [u for u in users if u.get('permission') == 1]
        last_admin = 'Nunca'
        if admin_users:
            admin_with_access = [u for u in admin_users if u.get('extra')]
            if admin_with_access:
                latest_admin = max(admin_with_access, key=lambda x: x.get('extra', ''))
                last_admin = latest_admin.get('extra', '')[:16] if latest_admin.get('extra') else 'Nunca'
        
        return {
            'verified_users': verified_percentage,
            'active_sessions': active_sessions,
            'last_admin_access': last_admin,
            'failed_logins': get_failed_login_count()
        }
    except Exception as e:
        log.error(f"Error obteniendo información de seguridad: {e}")
        return {'verified_users': 0, 'active_sessions': 0, 'last_admin_access': 'Error', 'failed_logins': 0}

def create_backup(system_path):
    """Crear backup completo del sistema en formato JSON"""
    try:
        import json
        backup_dir = os.path.join(system_path, 'backups')
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'backup_{timestamp}.json')
        
        users = USERPG.GET_ALL_USERS() or []
        posts = get_cached_posts()
        stats = get_system_stats()
        
        # Crear estructura de backup completa
        backup_data = {
            'metadata': {
                'version': '1.0',
                'created_at': datetime.datetime.now().isoformat(),
                'system_info': {
                    'os_name': stats.get('os_name', 'Desconocido'),
                    'python_version': stats.get('python_version', 'Desconocido'),
                    'hostname': stats.get('hostname', 'Desconocido')
                },
                'stats': {
                    'total_users': len(users),
                    'total_posts': len(posts),
                    'total_files': stats.get('files', 0)
                }
            },
            'users': users,
            'posts': posts,
            'config': {
                'email_verification_mode': os.getenv('EMAIL_VERIFICATION_MODE', '1'),
                'max_file_size_gb': os.getenv('MAX_FILE_SIZE_GB', '4'),
                'remember_me_days': os.getenv('REMEMBER_ME_DAYS', '30')
            }
        }
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, ensure_ascii=False, default=str)
        
        log.info(f"Backup completo creado: {backup_file}")
        return f'backup_{timestamp}.json'
    except Exception as e:
        log.error(f"Error creando backup: {e}")
        return None

def restore_backup(backup_file_path):
    """Restaurar backup desde archivo JSON"""
    try:
        import json
        import bcrypt
        
        with open(backup_file_path, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)
        
        if 'metadata' not in backup_data or backup_data['metadata'].get('version') != '1.0':
            return {'success': False, 'error': 'Formato de backup no válido'}
        
        restored_users = 0
        restored_posts = 0
        errors = []
        
        # Restaurar usuarios
        if 'users' in backup_data:
            for user in backup_data['users']:
                try:
                    # Verificar si el usuario ya existe
                    existing_user = USERPG.GET_USER('username', user['username'])
                    if existing_user:
                        log.debug(f"Usuario {user['username']} ya existe, saltando")
                        continue
                    
                    # Crear usuario con contraseña temporal
                    temp_password = 'temp123'
                    hashed_password = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    
                    result = USERPG.INSERT_USER(
                        user['username'], 
                        user['email'], 
                        hashed_password
                    )
                    
                    if 'creado correctamente' in result:
                        # Actualizar campos adicionales
                        if user.get('email_confirm') == 'true':
                            USERPG.EDITAR('email_confirm', user['username'], 'true')
                        if user.get('permission') == 1:
                            USERPG.EDITAR('permission', user['username'], 1)
                        if user.get('extra'):
                            USERPG.EDITAR('extra', user['username'], user['extra'])
                        
                        restored_users += 1
                    else:
                        errors.append(f"Error creando usuario {user['username']}: {result}")
                        
                except Exception as e:
                    errors.append(f"Error procesando usuario {user.get('username', 'desconocido')}: {str(e)}")
        
        # Restaurar posts
        if 'posts' in backup_data:
            for post in backup_data['posts']:
                try:
                    # Verificar si el post ya existe por título
                    existing_posts = BLOGPG.GET_BL('all') or []
                    if any(p.get('title') == post.get('title') for p in existing_posts):
                        log.debug(f"Post '{post.get('title')}' ya existe, saltando")
                        continue
                    
                    # Obtener ID del autor
                    author_id = post.get('creat_id')
                    if isinstance(author_id, str) and not author_id.isdigit():
                        # Es un username, obtener ID
                        author_data = USERPG.GET_USER('username', author_id)
                        if author_data:
                            author_id = author_data['id']
                        else:
                            # Crear usuario temporal si no existe
                            temp_password = bcrypt.hashpw('temp123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                            USERPG.INSERT_USER(author_id, f"{author_id}@restored.local", temp_password)
                            author_data = USERPG.GET_USER('username', author_id)
                            author_id = author_data['id'] if author_data else 1
                    
                    # Crear post
                    result = BLOGPG.INSERT_BL(
                        post.get('title', 'Post Restaurado'),
                        post.get('descript', ''),
                        post.get('content', ''),
                        post.get('tags', ''),
                        author_id
                    )
                    
                    if result == "Post creado correctamente":
                        restored_posts += 1
                    else:
                        errors.append(f"Error creando post '{post.get('title')}': {result}")
                        
                except Exception as e:
                    errors.append(f"Error procesando post '{post.get('title', 'desconocido')}': {str(e)}")
        
        # Limpiar cache
        global _posts_cache
        _posts_cache = None
        
        result_message = f"Restauración completada: {restored_users} usuarios, {restored_posts} posts"
        if errors:
            result_message += f". {len(errors)} errores encontrados."
        
        log.info(result_message)
        return {
            'success': True, 
            'message': result_message,
            'details': {
                'users': restored_users,
                'posts': restored_posts,
                'errors': errors[:5]  # Solo primeros 5 errores
            }
        }
        
    except Exception as e:
        log.error(f"Error restaurando backup: {e}")
        return {'success': False, 'error': str(e)}

def list_backups(system_path):
    """Listar backups disponibles"""
    try:
        backup_dir = os.path.join(system_path, 'backups')
        if not os.path.exists(backup_dir):
            return []
        
        backups = []
        for file in os.listdir(backup_dir):
            if file.endswith('.json') and file.startswith('backup_'):
                file_path = os.path.join(backup_dir, file)
                stat = os.stat(file_path)
                
                # Intentar leer metadata
                try:
                    import json
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    metadata = data.get('metadata', {})
                    stats = metadata.get('stats', {})
                except:
                    metadata = {}
                    stats = {}
                
                backups.append({
                    'filename': file,
                    'size': stat.st_size,
                    'created': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'users': stats.get('total_users', 0),
                    'posts': stats.get('total_posts', 0),
                    'files': stats.get('total_files', 0)
                })
        
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups
        
    except Exception as e:
        log.error(f"Error listando backups: {e}")
        return []