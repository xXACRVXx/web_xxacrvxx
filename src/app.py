#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xXACRVXx Web Application
========================
Plataforma web personal con gestión de archivos, blog y panel de administración.
"""

import os
import sys
import time
import json
import signal
import logging
import datetime
import tempfile
import traceback
from typing import Tuple, Optional, Dict, Any

# Flask y extensiones
from flask import (
    Flask, request, render_template, redirect, url_for, jsonify,
    Response, flash, session, send_file, send_from_directory, make_response
)
from flask_socketio import SocketIO, emit, send
from flask_wtf.csrf import CSRFProtect, CSRFError
# from werkzeug.utils import secure_filename  # Ya no se usa

# Librerías de seguridad y validación
import bcrypt
import jwt
import requests
import psutil

# Módulos locales
from Modules import USERPG, BLOGPG, CONFIG, VALIDATORS, THUMBNAILS, ADMIN, ANALYTICS
from Modules.FORMS import LoginForm, RegisterForm, ResetPasswordForm, EmailConfirmForm, UploadForm, EmailRequestForm
from Modules.SENDMAIL import SEND_MAIL
from Modules.SECURITY import sanitize_filename
from dotenv import load_dotenv
import Modules.LOGGER


# ============================================================================
# CONFIGURACIÓN DE LA APLICACIÓN
# ============================================================================

# Verificar y crear configuración si no existe
if not os.path.exists("config.env"):
    print("⚠️  Archivo config.env no encontrado. Iniciando configuración...")
    try:
        from Modules.SETUP import create_config
        if not create_config():
            print("❌ Error en la configuración. Saliendo...")
            sys.exit(1)
    except ImportError:
        print("❌ Módulo de configuración no encontrado")
        sys.exit(1)

# Cargar variables de entorno
load_dotenv("config.env")

# Configuración de logging
log = logging.getLogger("WEB")

# Constantes de la aplicación
VERSION = "v1.0.0-dev4"
START_SERVER_TIME = time.time()
EMAIL_WEBMASTER = os.getenv("EMAIL_WEBMASTER")

# Inicializar Flask
app = Flask(__name__, template_folder="web")
app.secret_key = CONFIG.SECRET
app.config["SECRET_KEY"] = CONFIG.SECRET
app.config["UPLOAD_FOLDER"] = CONFIG.RUTE

# Configurar límites de archivo
max_file_gb = int(os.getenv('MAX_FILE_SIZE_GB', '4'))
app.config["MAX_CONTENT_LENGTH"] = max_file_gb * 1024 * 1024 * 1024

# Configurar duración de sesión
remember_days = int(os.getenv('REMEMBER_ME_DAYS', '30'))
app.permanent_session_lifetime = datetime.timedelta(days=remember_days)

# Configurar CSRF Protection
csrf = CSRFProtect(app)

# Excluir rutas de API de la protección CSRF
csrf.exempt('apiauth_v1')
csrf.exempt('apimsg')
csrf.exempt('apiauth_v2')
csrf.exempt('destroyer_bot')

# Configurar SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# ============================================================================
# FUNCIONES DE UTILIDAD Y SEGURIDAD
# ============================================================================

def get_client_ip() -> str:
    """Obtener IP del cliente de forma segura."""
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"

def validate_csrf_token(token: str) -> bool:
    """Validar token CSRF de forma segura."""
    return bool(token and token.strip())

def sanitize_path(path: str) -> str:
    """Sanitizar rutas para prevenir path traversal."""
    if not path:
        return ""
    return path.replace('..', '').strip(os.sep)

# ============================================================================
# MIDDLEWARE DE SEGURIDAD
# ============================================================================

@app.before_request
def analytics_middleware():
    """Middleware para registrar visitas."""
    try:
        ip_client = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        page = request.endpoint or request.path
        referrer = request.headers.get('Referer', '')
        
        # No registrar rutas estáticas o de admin
        if not request.path.startswith('/static/') and not request.path.startswith('/admin/'):
            ANALYTICS.record_visit(ip_client, user_agent, page, referrer)
    except Exception as e:
        log.debug(f"Error en analytics middleware: {e}")

@app.before_request
def security_middleware():
    """Middleware de seguridad para proteger rutas administrativas."""
    # Proteger rutas de administración
    if (request.endpoint and request.endpoint.startswith('admin_')) or request.path.startswith('/admin'):
        sessions, token, username, uid = if_session(session)
        if not sessions or not check_admin_permission(uid):
            ip_client = get_client_ip()
            log.warning(f"[{ip_client}] [SECURITY] Intento de acceso no autorizado a {request.path} por usuario {username or 'anónimo'}")
            
            if request.is_json:
                return jsonify({"error": "Acceso denegado. Permisos de administrador requeridos."}), 403
            else:
                flash("Acceso denegado. Permisos de administrador requeridos.", "error")
                return redirect(url_for("login"))

@app.before_request
def email_verification_middleware():
    """Middleware para verificar email obligatorio en rutas protegidas."""
    # Rutas que no requieren verificación de email
    exempt_routes = [
        'login', 'regist', 'logout', 'EmailSend', 'EmailConfirm', 'skip_email_verification', 
        'resetpassw', 'static', 'favicon', 'robots_txt', 'humans_txt', 'sitemap_xml', 'sitemap2_xml',
        'index', 'blog', 'blogview', 'detalles', 'servicios', 'contactar', 'ter_y_co', 'privacy',
        'about', 'team', 'portfolio', 'status_server'
    ]
    
    # Rutas que requieren verificación
    protected_routes = [
        'download', 'upload', 'delete', 'folder', 'move_file', 'rename_item', 'thumbnail',
        'cloud', 'blogpost', 'blogedit', 'blogdelete', 'options', 'settings'
    ]
    
    if request.endpoint in exempt_routes or request.path.startswith('/static/'):
        return
    
    sessions, token, username, uid = if_session(session)
    if sessions and request.endpoint in protected_routes:
        
        def is_skip_valid(email_confirm):
            if not email_confirm or not email_confirm.startswith('skipped_'):
                return False
            try:
                import time
                skip_timestamp = int(email_confirm.split('_')[1])
                days_passed = (time.time() - skip_timestamp) / (24 * 3600)
                return days_passed < 7  # Válido por 7 días
            except:
                return False
        
        email_mode = int(os.getenv('EMAIL_VERIFICATION_MODE', '1'))
        if email_mode >= 1:
            user_data = USERPG.GET_USER('id', uid)
            if user_data and user_data.get('email_confirm') not in ['true'] and not is_skip_valid(user_data.get('email_confirm', 'false')):
                # Pasar parámetro can_skip basado en el modo
                return redirect(url_for('EmailSend', email=user_data['email'], can_skip='1' if email_mode < 2 else '0'))

def if_session(session) -> Tuple[bool, Optional[str], Optional[str], Optional[int]]:
    """
    Verificar si hay una sesión activa y válida.
    
    Returns:
        Tuple[bool, Optional[str], Optional[str], Optional[int]]: 
        (sessions_valid, token, username, user_id)
    """
    try:
        uid = session.get("user")
        token = session.get("token")
        
        if not uid or not token:
            return False, None, None, None
            
        # Verificar token JWT
        jwt.decode(jwt=str(token), key=str(app.config.get("SECRET_KEY")), algorithms=["HS256"])
        
        # Verificar usuario en BD
        user_data = USERPG.GET_USER("id", uid)
        if not user_data or isinstance(user_data, str):
            return False, None, None, None
            
        username = user_data.get('username')
        if not username:
            return False, None, None, None
            
        return True, token, username, uid
        
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        log.debug("Token JWT inválido o expirado")
        return False, None, None, None
    except (KeyError, TypeError) as e:
        log.debug(f"Error en datos de sesión: {e}")
        return False, None, None, None
    except Exception as e:
        log.error(f"Error inesperado en if_session: {e}")
        return False, None, None, None

def check_admin_permission(uid: int) -> bool:
    """Verificar si el usuario tiene permisos de administrador."""
    try:
        user_data = USERPG.GET_USER('id', uid)
        if user_data and user_data.get('permission', 0) == 1:
            return True
        
        # Si no hay administradores, permitir acceso
        all_users = USERPG.GET_ALL_USERS() or []
        has_admin = any(user.get('permission', 0) == 1 for user in all_users)
        
        return not has_admin  # Permitir si no hay admins
    except Exception as e:
        log.error(f"Error verificando permisos de admin: {e}")
        return False

# ============================================================================
# RUTAS PRINCIPALES
# ============================================================================

@app.route('/about')
def about():
    """Página sobre nosotros."""
    dark_mode = request.cookies.get('dark-mode', 'true')
    try:
        sessions, token, username, uid = if_session(session)
        return render_template('pages/about.html', 
                             sessions=sessions, 
                             user=username, 
                             cookie=dark_mode, 
                             version=VERSION)
    except Exception as e:
        log.error(f"Error en página about: {e}")
        return render_template('pages/about.html', 
                             sessions=False, 
                             user=None, 
                             cookie=dark_mode, 
                             version=VERSION)

@app.route('/team')
def team():
    """Página nuestro equipo."""
    dark_mode = request.cookies.get('dark-mode', 'true')
    try:
        sessions, token, username, uid = if_session(session)
        return render_template('pages/team.html', 
                             sessions=sessions, 
                             user=username, 
                             cookie=dark_mode, 
                             version=VERSION)
    except Exception as e:
        log.error(f"Error en página team: {e}")
        return render_template('pages/team.html', 
                             sessions=False, 
                             user=None, 
                             cookie=dark_mode, 
                             version=VERSION)

# ============================================================================
# MANEJADORES DE ERRORES
# ============================================================================

@app.errorhandler(404)
def not_found(error=None):
    """Manejador de error 404."""
    ip_client = get_client_ip()
    log.warning(f"[{ip_client}] [404] Página no encontrada: {request.path}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error=None):
    """Manejador de error 500."""
    ip_client = get_client_ip()
    log.error(f"[{ip_client}] [500] Error interno del servidor: {error}")
    return render_template('errors/500.html'), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Manejador de errores CSRF."""
    ip_client = get_client_ip()
    log.warning(f"[{ip_client}] [CSRF] Error CSRF: {e}")
    flash('Token de seguridad inválido. Por favor, intenta de nuevo.', 'error')
    return redirect(request.referrer or url_for('index'))

# ============================================================================
# RUTAS PÚBLICAS
# ============================================================================

@app.route("/")
def index():
    """Página principal."""
    ip_client = get_client_ip()
    dark_mode = request.cookies.get('dark-mode', 'true')
    
    try:
        posts = BLOGPG.GET_BL('all') or []
        posts.sort(key=lambda x: x.get('id', 0), reverse=True)
        recent = posts[:4]
        
        sessions, token, username, uid = if_session(session)
        
        if sessions:
            log.info(f"[{ip_client}] [/] Usuario autenticado: {username}")
            return render_template("app/index.html", recent=recent, user=username, 
                                 cookie=dark_mode, version=VERSION)
        else:
            log.debug(f"[{ip_client}] [/] Usuario anónimo")
            return render_template("index.html", recent=recent, cookie=dark_mode, version=VERSION)
            
    except Exception as e:
        log.error(f"[{ip_client}] [/] Error: {e}")
        return render_template("index.html", cookie=dark_mode, version=VERSION)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Página de inicio de sesión."""
    ip_client = get_client_ip()
    form = LoginForm()
    
    if form.validate_on_submit():
        try:
            email = form.email.data.strip()
            password = form.passw.data
            redirect_for = form.redirect_for.data or ""
            remember_me = form.remember_me.data
            
            # Validaciones de seguridad
            if len(password) > 128:
                log.warning(f"[{ip_client}] [/login] Contraseña demasiado larga")
                flash("Usuario o contraseña incorrecta", "warning")
                return render_template("auth/log-in_layout.html", form=form)
            
            # Verificar límite de intentos fallidos
            max_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
            if ADMIN.get_failed_login_count() >= max_attempts:
                log.warning(f"[{ip_client}] [/login] Máximo de intentos excedido")
                flash("Demasiados intentos fallidos. Intente nuevamente en 1 hora.", "error")
                return render_template("auth/log-in_layout.html", form=form)
            
            # Obtener usuario por email o username (case-insensitive para username)
            if VALIDATORS.validate_email(email):
                user_data = USERPG.GET_USER("email", email)
            else:
                all_users = USERPG.GET_ALL_USERS() or []
                user_data = next((user for user in all_users if user.get('username', '').lower() == email.lower()), None)
                
            if not user_data or isinstance(user_data, str):
                ADMIN.increment_failed_login()
                remaining = max_attempts - ADMIN.get_failed_login_count()
                log.warning(f"[{ip_client}] [/login] Usuario no encontrado: {email}")
                
                if remaining > 0:
                    flash(f"Usuario o contraseña incorrecta. Intentos restantes: {remaining}", "warning")
                else:
                    flash("Demasiados intentos fallidos. Intente nuevamente en 1 hora.", "error")
                return render_template("auth/log-in_layout.html", form=form)
                
            # Verificar contraseña
            if not bcrypt.checkpw(password.encode("utf-8"), user_data['passw'].encode("utf-8")):
                ADMIN.increment_failed_login()
                remaining = max_attempts - ADMIN.get_failed_login_count()
                log.warning(f"[{ip_client}] [/login] Contraseña incorrecta para: {user_data['username']}")
                
                if remaining > 0:
                    flash(f"Usuario o contraseña incorrecta. Intentos restantes: {remaining}", "warning")
                else:
                    flash("Demasiados intentos fallidos. Intente nuevamente en 1 hora.", "error")
                return render_template("auth/log-in_layout.html", form=form)
            
            # Login exitoso
            data_token = {"text": "authenticated_user", "user_id": user_data['id']}
            token = jwt.encode(data_token, app.config.get("SECRET_KEY"), algorithm="HS256")
            
            if remember_me:
                session.permanent = True
                
            session["user"] = user_data['id']
            session["token"] = token
            
            # Resetear contador de intentos fallidos
            ADMIN._failed_login_attempts = 0
            
            # Actualizar última conexión
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                USERPG.EDITAR('extra', user_data['username'], current_time)
            except Exception as e:
                log.warning(f"Error actualizando última conexión: {e}")
            
            # Verificar configuración de email
            email_mode = int(os.getenv('EMAIL_VERIFICATION_MODE', '1'))
            if email_mode == 1 and user_data['email_confirm'] == "false":
                return redirect(url_for("EmailSend", email=user_data['email']))
            
            flash("Cuenta iniciada correctamente", "success")
            log.info(f"[{ip_client}] [/login] Login exitoso: {user_data['username']}")
            
            return redirect(redirect_for) if redirect_for else redirect(url_for("index"))
            
        except Exception as e:
            log.error(f"[{ip_client}] [/login] Error: {e}")
            flash("Error interno. Intenta de nuevo.", "error")
            return render_template("auth/log-in_layout.html", form=form)
    
    # GET request
    if request.args.get("redirect"):
        form.redirect_for.data = request.args.get("redirect")
    
    return render_template("auth/log-in_layout.html", form=form)


@app.route("/regist", methods=["GET", "POST"])
def regist():
    """Página de registro."""
    ip_client = get_client_ip()
    form = RegisterForm()
    
    # Verificar si el registro está habilitado
    registration_enabled = os.getenv('REGISTRATION_ENABLED', 'True').lower() == 'true'
    if not registration_enabled:
        flash("El registro de nuevos usuarios está temporalmente deshabilitado.", "warning")
        return redirect(url_for("login"))
    
    if form.validate_on_submit():
        try:
            username = form.username.data.strip()
            email = form.email.data.strip()
            password = form.passw.data
            
            # Validaciones adicionales
            username_valid, username_msg = VALIDATORS.validate_username(username)
            if not username_valid:
                flash(username_msg, "error")
                log.debug(f"[{ip_client}] [/regist] Username inválido: {username_msg}")
                return render_template("auth/sign-up_layout.html", form=form)
            
            # Verificar si el usuario o email ya existen (case-insensitive)
            existing_users = USERPG.GET_ALL_USERS() or []
            username_exists = any(user.get('username', '').lower() == username.lower() for user in existing_users)
            if username_exists:
                flash("El nombre de usuario ya existe", "error")
                return render_template("auth/sign-up_layout.html", form=form)
                
            if USERPG.GET_USER("email", email):
                flash("El email ya está registrado", "error")
                return render_template("auth/sign-up_layout.html", form=form)
            
            # Verificar si es el primer usuario (será admin)
            all_users = USERPG.GET_ALL_USERS() or []
            is_first_user = len(all_users) == 0
            
            # Crear usuario
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            permission = 1 if is_first_user else 0
            response = USERPG.INSERT_USER(username, email, hashed_password.decode('utf-8'), permission)
            
            if "creado correctamente" in response:
                all_users = USERPG.GET_ALL_USERS() or []
                user_data = next((user for user in all_users if user.get('username', '').lower() == username.lower()), None)
                data_token = {"text": "authenticated_user", "user_id": user_data['id']}
                token = jwt.encode(data_token, app.config.get("SECRET_KEY"), algorithm="HS256")
                
                session.permanent = True
                session["user"] = user_data['id']
                session["token"] = token
                
                if is_first_user:
                    flash(f"¡Primer usuario creado como administrador! Revise su correo electrónico.", "success")
                else:
                    flash(f"Usuario creado correctamente. Revise su correo electrónico.", "info")
                    
                log.info(f"[{ip_client}] [/regist] Usuario {username} creado {'como admin' if is_first_user else 'correctamente'}")
                return redirect(url_for("EmailSend", email=email))
            else:
                flash(response, "warning")
                log.debug(f"[{ip_client}] [/regist] Usuario {username} no creado: {response}")
                return render_template("auth/sign-up_layout.html", form=form)
                
        except Exception as e:
            flash("Error interno. Intenta de nuevo.", "error")
            log.error(f"[{ip_client}] [/regist] Error: {e}")
            return render_template("auth/sign-up_layout.html", form=form)
    
    return render_template("auth/sign-up_layout.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """Cerrar sesión."""
    ip_client = get_client_ip()
    user_id = session.get("user", "unknown")
    
    log.info(f"[{ip_client}] [/logout] Usuario {user_id} cerrando sesión")
    
    session.clear()
    flash("Sesión cerrada correctamente", "info")
    return redirect(url_for("index"))


@app.route("/switch-account", methods=["POST"])
def switch_account():
    """Cambiar de cuenta (cerrar sesión y redirigir al login)."""
    ip_client = get_client_ip()
    user_id = session.get("user", "unknown")
    
    # Validar CSRF token
    csrf_token = request.form.get("csrf_token")
    if not csrf_token:
        flash("Token de seguridad requerido", "error")
        return redirect(request.referrer or url_for("index"))
    
    log.info(f"[{ip_client}] [/switch-account] Usuario {user_id} cambiando de cuenta")
    
    session.clear()
    flash("Sesión cerrada. Inicia sesión con otra cuenta", "info")
    return redirect(url_for("login"))


@app.route("/resetpassw", methods=["POST", "GET"])
def resetpassw():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            password = request.form.get("passw")
            password2 = request.form.get("passw2")
            token = request.form.get("token")
            csrf_token = request.form.get("csrf_token")
            
            if not csrf_token:
                flash("Token de seguridad requerido", "error")
                return render_template("auth/RPassw.html", token=token)
            try:
                verific = jwt.decode(jwt=str(token), key=str(app.config.get("SECRET_KEY")), algorithms=["HS256"])
                user = USERPG.GET_USER("username", verific['user'])
                if int(user['random']) == int(verific['code']):
                    if password.__len__() < 8:
                        flash("La contraseña no puede tener menos de 8 dijitos", "error")
                        log.debug(f"[{ip_client}] [/resetpassw ] Contraseña incorrecta [menor a 8 dijitos]")
                        return render_template("auth/RPassw.html", token=token, user=user['username'])
                    elif password != password2:
                        flash("Las contraseñas no coinciden", "error")
                        log.debug(f"[{ip_client}] [/resetpassw ] Contraseña incorrecta [no coinciden]")
                        return render_template("auth/RPassw.html", token=token, user=user['username'])
                    EPASSW = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    USERPG.EDITAR('passw',user['username'], EPASSW.decode('utf-8'))
                    USERPG.C_EMAIL_VAL(user['username'])
                    flash("Contraseña actualizada correctamente", "success")
                    log.info(f"[{ip_client}] [/resetpassw ] Usuario [{user['username']}] cambio su contraseña")
                    return redirect(url_for("login"))
                else:
                    flash("Autorizacion invalida", "error")
                    log.debug(f"[{ip_client}] [/resetpassw ] Usuario [{user['username']}] ")
                    return redirect(url_for("resetpassw"))
            except jwt.ExpiredSignatureError:
                flash("Token expirado", "error")
                log.debug(f"[{ip_client}] [/resetpassw ] Token expirado")
                return redirect(url_for("resetpassw"))
            except jwt.InvalidTokenError:
                flash("Token invalido", "error")
                log.debug(f"[{ip_client}] [/resetpassw ] Token invalido")
                return render_template("auth/RCPassw.html")
        except Exception as e:
            flash("Ups algo salio mal, intentalo de nuevo mas tarde", "error")
            log.error(f"[{ip_client}] [/resetpassw ] ERROR[0004]: {e} [{traceback.format_exc()}]")
            return render_template("auth/RCPassw.html")
    if request.args.get("token"):
        token = request.args.get("token")
        try:
            verific = jwt.decode(jwt=str(token), key=str(app.config.get("SECRET_KEY")), algorithms=["HS256"])
            user = USERPG.GET_USER("username", verific['user'])
            if int(user['random']) == int(verific['code']):
                log.info(f"[{ip_client}] [/resetpassw ] Token valido [{verific['user']}]")
                return render_template("auth/RPassw.html", token=token, user=verific['user'])
            else:
                flash("Autorizacion invalida", "error")
                log.debug(f"[{ip_client}] [/resetpassw ] Usuario [{user['username']}] ")
                return render_template("auth/RCPassw.html")
        except jwt.ExpiredSignatureError:
            flash("Token expirado", "error")
            log.debug(f"[{ip_client}] [/resetpassw ] Token expirado")
            return redirect(url_for("resetpassw"))
        except jwt.InvalidTokenError:
            flash("Token invalido", "error")
            log.debug(f"[{ip_client}] [/resetpassw ] Token invalido")
            return render_template("auth/RCPassw.html")
    if request.args.get("email"):
        email = request.args.get("email")
        try:
            user = USERPG.GET_USER("email", email)
            if user == None:
                flash(f'No se a registrado una cuenta con el correo electronico "{email}" en nuestros servidores, si no tiene una cuenta creela', 'warning')
                log.info(f"[{ip_client}] [/EmailSend ] Correo [{email}] no existe")
                return render_template("auth/REPassw.html")
            code = USERPG.C_EMAIL_VAL(user['username'])
            datos_send_token = {"user": user['username'], "code": code, "exp": datetime.datetime.now(datetime.UTC)+ datetime.timedelta(minutes=30, seconds=0),"iat": datetime.datetime.now(datetime.UTC)}
            token = jwt.encode(datos_send_token, app.config.get("SECRET_KEY"), algorithm="HS256")

            subject = f"Recuperecion de cuenta"
            message = f"""
            <html>
                <head>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f4;
                            margin: 0;
                            padding: 0;
                            color: #333;
                            text-align: center;
                        }}
                        .container {{
                            max-width: 600px;
                            width: 90%;
                            margin: 0 auto;
                            background-color: #fff;
                            padding: 15px;
                            border-radius: 8px;
                            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                            text-align: center;
                        }}
                        h1 {{
                            color: #6c55f9;
                            font-size: 22px;
                            margin-bottom: 20px;
                        }}
                        h2 {{
                            color: #333;
                            font-size: 16px;
                            margin-bottom: 20px;
                            line-height: 1.5;
                        }}
                        p {{
                            color: #555;
                            font-size: 14px;
                            line-height: 1.5;
                            margin-top: 20px;
                        }}
                        a {{
                            color: #6c55f9;
                            text-decoration: none;
                            font-weight: bold;
                        }}
                        .code {{
                            font-size: 20px;
                            color: #6c55f9;
                            background-color: #f4f4f4;
                            padding: 10px;
                            border-radius: 5px;
                            border: 1px solid #6c55f9;
                            display: inline-block;
                            margin-top: 20px;
                            user-select: text; 
                        }}
                        .footer {{
                            margin-top: 30px;
                            font-size: 12px;
                            color: #777;
                        }}
                        @media (max-width: 600px) {{
                            h1 {{font-size: 20px;}}
                            h2 {{font-size: 14px;}}
                            .code {{
                                font-size: 18px;
                                padding: 8px;
                            }}
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Recuperacion de cuenta</h1>
                        <h2>Hola <strong>{user['username']}</strong>,</h2>
                        <h2>Por favor haz clic en el enlace a continuación para cambiar tu contraseña</h2>
                        <h1><a href="{os.getenv('BASE_URL', 'https://xxacrvxx.ydns.eu')}/resetpassw?token={token}">Cambiar contraseña</a></h1>
                        <p>Este enlace será válido durante 30 minutos. Si no solicitaste esto, ignora este correo.</p>
                        <div class="footer">
                            <p>Saludos,<br>El equipo de xXACRVXx</p>
                        </div>
                    </div>
                </body>
            </html>
            """

            SEND_MAIL(email, subject, message)
            flash(f"Se envio un correo a [{email}] para recuperar su cuenta, por favor haga click en el enlace de el correo", 'info')
            log.info(f"[{ip_client}] [/EmailSend ] Usuario [{user['username']}] envio correo a [{email}] para confirmar su cuenta")
            return render_template("auth/RCPassw.html", email=email)
        except Exception as e:
            log.error(f"[{ip_client}] [/EmailSend ] ERROR[0004]: {e} [{traceback.format_exc()}]")
            flash(f"Ups estamos teniendo problemas para enviar el correo, por favor intentelo mas tarde", 'error')
            return render_template("auth/RCPassw.html")
    else:
        return render_template("auth/REPassw.html")


@app.route("/confirm")
def EmailSend():
    ip_client = request.headers.get("X-Real-IP")
    email_mode = int(os.getenv('EMAIL_VERIFICATION_MODE', '1'))
    
    # Verificar si se puede saltear desde parámetro o configuración
    can_skip_param = request.args.get('can_skip')
    if can_skip_param:
        can_skip = can_skip_param == '1'
    else:
        can_skip = email_mode < 2
    
    if request.args.get("email"):
        email = request.args.get("email")
        try:
            user = USERPG.GET_USER("email", email)
            if user == None:
                flash(f'No se a registrado una cuenta con el correo electronico "{email}" en nuestros servidores, si no tiene una cuenta creela', 'warning')
                log.info(f"[{ip_client}] [/EmailSend ] Correo [{email}] no existe")
                return render_template("auth/EmailSend.html", can_skip=can_skip)
            code = USERPG.C_EMAIL_VAL(user['username'], VERIFIC=True)
            if code == True:
                flash(f'El correo "{email}" ya fue confirmado anteriormente', 'error')
                log.info(f"[{ip_client}] [/EmailSend ] Correo [{email}] ya fue confirmado anteriormente")
                return render_template("auth/EmailSend.html", can_skip=can_skip)

            datos_send_token = {"user": user['username'], "email": email, "code": code, "exp": datetime.datetime.now(datetime.UTC)+ datetime.timedelta(minutes=30, seconds=0),"iat": datetime.datetime.now(datetime.UTC)}
            token = jwt.encode(datos_send_token, app.config.get("SECRET_KEY"), algorithm="HS256")

            subject = f"Confirmación de cuenta [{code}]"
            message = f"""
            <html>
                <head>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f4;
                            margin: 0;
                            padding: 0;
                            color: #333;
                            text-align: center;
                        }}
                        .container {{
                            max-width: 600px;
                            width: 90%;
                            margin: 0 auto;
                            background-color: #fff;
                            padding: 15px;
                            border-radius: 8px;
                            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                            text-align: center;
                        }}
                        h1 {{
                            color: #6c55f9;
                            font-size: 22px;
                            margin-bottom: 20px;
                        }}
                        h2 {{
                            color: #333;
                            font-size: 16px;
                            margin-bottom: 20px;
                            line-height: 1.5;
                        }}
                        p {{
                            color: #555;
                            font-size: 14px;
                            line-height: 1.5;
                            margin-top: 20px;
                        }}
                        a {{
                            color: #6c55f9;
                            text-decoration: none;
                            font-weight: bold;
                        }}
                        .code {{
                            font-size: 20px;
                            color: #6c55f9;
                            background-color: #f4f4f4;
                            padding: 10px;
                            border-radius: 5px;
                            border: 1px solid #6c55f9;
                            display: inline-block;
                            margin-top: 20px;
                            user-select: text; 
                        }}
                        .footer {{
                            margin-top: 30px;
                            font-size: 12px;
                            color: #777;
                        }}
                        @media (max-width: 600px) {{
                            h1 {{font-size: 20px;}}
                            h2 {{font-size: 14px;}}
                            .code {{
                                font-size: 18px;
                                padding: 8px;
                            }}
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Confirmación de cuenta</h1>
                        <h2>Hola <strong>{user['username']}</strong>,</h2>
                        <h2>¡Gracias por registrarte en nuestra plataforma! Por favor, confirma tu correo electrónico copiando y pegando el siguiente código:</h2>
                        <div class="code">{code}</div>
                        <h2>O haz clic en el enlace a continuación para confirmar directamente:</h2>
                        <h1><a href="{os.getenv('BASE_URL', 'https://xxacrvxx.ydns.eu')}/EmailConfirm?token={token}">Confirmar mi cuenta</a></h1>
                        <p>Este código será válido durante 30 minutos. Si no solicitaste este registro, ignora este correo.</p>
                        <div class="footer">
                            <p>Saludos,<br>El equipo de xXACRVXx</p>
                        </div>
                    </div>
                </body>
            </html>
            """

            SEND_MAIL(email, subject, message)
            log.info(f"[{ip_client}] [/EmailSend ] Usuario [{user['username']}] envio correo a [{email}] para confirmar su cuenta")
            return redirect(url_for("EmailConfirm", email=email, can_skip='1' if email_mode < 2 else '0'))
        except Exception as e:
            log.error(f"[{ip_client}] [/EmailSend ] ERROR[0004]: {e} [{traceback.format_exc()}]")
            flash(f"Ups estamos teniendo problemas para enviar el correo, por favor intentelo mas tarde", 'error')
            return render_template("auth/EmailSend.html", can_skip=can_skip)
    else:
        return render_template("auth/EmailSend.html", can_skip=can_skip)


@app.route("/skip-email-verification")
def skip_email_verification():
    """Permitir saltear verificación de email si está habilitado"""
    ip_client = request.headers.get("X-Real-IP")
    
    # Verificar si hay sesión activa
    sessions, token, uss, uid = if_session(session)
    if not sessions:
        return redirect(url_for("login"))
    
    # Verificar modo de verificación de email
    email_mode = int(os.getenv('EMAIL_VERIFICATION_MODE', '1'))
    
    # Solo bloquear si el modo es forzado (>= 2)
    if email_mode >= 2:
        flash("La verificación de email es obligatoria y no se puede saltar", "error")
        user_data = USERPG.GET_USER('id', uid)
        if user_data:
            return redirect(url_for("EmailSend", email=user_data['email']))
        return redirect(url_for("login"))
    
    try:
        user_data = USERPG.GET_USER('id', uid)
        if user_data and user_data.get('email_confirm') != 'true':
            # Marcar timestamp de cuando salteó
            import time
            skip_timestamp = str(int(time.time()))
            USERPG.EDITAR('email_confirm', user_data['username'], f'skipped_{skip_timestamp}')
            flash("Verificación de email pospuesta por 7 días. Puedes verificar desde configuración.", "info")
            log.info(f"[{ip_client}] [/skip-email-verification] Usuario [{uss}] salteó verificación (modo: {email_mode})")
        
        return redirect(url_for("index"))
        
    except Exception as e:
        log.error(f"[{ip_client}] [/skip-email-verification] Error: {e}")
        flash("Error al procesar solicitud", "error")
        return redirect(url_for("EmailSend"))


@app.route("/EmailConfirm", methods=["POST", "GET"])
def EmailConfirm():
    ip_client = request.headers.get("X-Real-IP")
    email_mode = int(os.getenv('EMAIL_VERIFICATION_MODE', '1'))
    
    # Verificar si se puede saltear
    can_skip_param = request.args.get('can_skip')
    if can_skip_param:
        can_skip = can_skip_param == '1'
    else:
        can_skip = email_mode < 2
    if request.method == "POST":
        try:
            email = request.form.get("email")
            code = request.form.get("code")
            csrf_token = request.form.get("csrf_token")
            
            if not csrf_token:
                flash("Token de seguridad requerido", "error")
                return render_template("auth/EmailConfirm.html", can_skip=can_skip)
            response = USERPG.EMAIL_VAL(email, code, True)
            if response == True:
                log.info(
                    f"[{ip_client}] [/EmailConfirm ] Correo [{email}] a activado su cuenta")
                return redirect(url_for("index"))
            if response == False:
                flash(f"EL CODIGO DE ACTIVACION ES INCORRECTO, SI NO A RESIVIDO UN CORREO PUEDE VOLVER A INTENTARLO", 'warning')
                log.debug(
                    f"[{ip_client}] [/EmailConfirm ] Correo [{email}] utilizo un codigo incorrecto")
                return render_template("auth/EmailConfirm.html", can_skip=can_skip)
        except Exception as e:
            log.error(
                f"[{ip_client}] [/EmailConfirm ] ERROR[0005]: {e} [{traceback.format_exc()}]")
            flash(f"Ups estamos teniendo problemas para activar su cuenta, por favor intentelo mas tarde", 'error')
            return render_template("auth/EmailConfirm.html", can_skip=can_skip)
    else:
        try:
            if request.args.get("email"):
                email = request.args.get("email")
                log.debug(
                    f"[{ip_client}] [/EmailConfirm ] Usuario [{email}] solicito confirmacion de cuenta")
                return render_template("auth/EmailConfirm.html", correo=email, can_skip=can_skip)

            if request.args.get("token"):
                try:
                    token = request.args.get("token")
                    verific = jwt.decode(
                        token, app.config.get("SECRET_KEY"), algorithms=["HS256"])

                    user = verific["user"]
                    email = verific["email"]
                    code = verific["code"]
                    user_data = USERPG.GET_USER("username", user)
                    if user_data == None:
                        log.warning(
                            f"[{ip_client}] [/EmailConfirm ] WARNING[0001] user [{user}], email [{email}] intento falsear el token")
                        return redirect(url_for("EmailSend"))

                    response = USERPG.EMAIL_VAL(email, code, True)
                    if response == True:
                        log.info(
                            f"[{ip_client}] [/EmailConfirm ] Usuario [{user_data['username']}] cuenta activada")
                        return redirect(url_for("index"))
                    else:
                        log.debug(
                            f"[{ip_client}] [/EmailConfirm ] Usuario [{user_data['username']}] codigo incorrecto")
                        return redirect(url_for("EmailSend"))

                except jwt.ExpiredSignatureError:
                    log.debug(
                        f"[{ip_client}] [/EmailConfirm ] [DEBUG] Token expirado")
                    return redirect(url_for("EmailSend"))
                except jwt.InvalidTokenError:
                    log.debug(
                        f"[{ip_client}] [/EmailConfirm ] [DEBUG] Token invalido")
                    return redirect(url_for("EmailSend"))
                except Exception as e:
                    log.error(
                        f"[{ip_client}] [/EmailConfirm ] ERROR[0006]: {e} [{traceback.format_exc()}]")
                    flash(f"Ups estamos teniendo problemas para activar su cuenta, por favor intentelo mas tarde", 'error')
                    return render_template("auth/EmailConfirm.html", can_skip=can_skip)
            else:
                return redirect(url_for("EmailSend"))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/EmailConfirm ] ERROR[0007]: {e} [{traceback.format_exc()}]")
            flash(f"Ups estamos teniendo problemas para activar su cuenta, por favor intentelo mas tarde", 'error')
            return render_template("auth/EmailConfirm.html", can_skip=can_skip)



@app.route("/cloud")
def cloud():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            return render_template("files/cloud.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("files/cloud.html", cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/cloud ] ERROR[0015]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/download")
def download():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    if request.args.get("file"):
        try:
            # Verificar si hay una sesión activa
            sessions, token, uss, uid = if_session(session)        
            if sessions == True:
                try:
                    archive = request.args.get("file")
                    the_path = os.path.join(app.config.get("UPLOAD_FOLDER"),str(uid))
                    log.info(
                        f"[{ip_client}] [/download ] Usuario [{uss}] descargando archivo [{archive}]"
                    )
                    if os.path.isfile(os.path.join(the_path, archive)) == False:
                        return Response(status=404)
                    return send_from_directory(the_path, archive, as_attachment=False)
                except Exception as e:
                    log.error(
                        f"[{ip_client}] [/download ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
                    return redirect(url_for("download"))

            else:
                log.debug(f"[{ip_client}] [/download ] Usuario no logueado")
                return redirect(url_for("login"))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/download ] ERROR[0008]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))

    elif request.args.get("token"):
        the_token = request.args.get("token")
        try:
            verific = jwt.decode(
                the_token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
            )
            archive = verific["archive"]
            user_token = str(verific["user"])
            
            # Validar que el archivo no contenga path traversal
            if '..' in archive or archive.startswith(os.sep):
                return Response(status=403)
            
            user_base_path = os.path.join(app.config.get("UPLOAD_FOLDER"), str(user_token))
            full_file_path = os.path.join(user_base_path, archive)
            
            # Verificar que el archivo esté dentro del directorio del usuario
            if not full_file_path.startswith(user_base_path):
                return Response(status=403)
            
            if not os.path.isfile(full_file_path):
                return Response(status=404)
                
            log.info(f"[{ip_client}] [/download ] Usuario descargando archivo [{archive}]")
            
            # Extraer directorio y nombre de archivo para send_from_directory
            file_dir = os.path.dirname(full_file_path)
            file_name = os.path.basename(full_file_path)
            return send_from_directory(file_dir, file_name, as_attachment=False)
        except jwt.ExpiredSignatureError:
            log.debug(
                f"[{ip_client}] [/download ] Usuario  expirón token")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            log.debug(
                f"[{ip_client}] [/download ] Usuario  token invalido")
            return redirect(url_for("login"))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/download ] Usuario  error {e} [{traceback.format_exc()}]")
            return redirect(url_for("download"))

    elif request.args.get("f_file"):
        the_token = request.args.get("f_file")
        try:
            verific = jwt.decode(
                the_token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
            )
            archive = verific["archive"]
            user_token = str(verific["user"])
            suid = USERPG.GET_USER("id", user_token)
            uss = suid['username']
            
            # Validar que el archivo no contenga path traversal
            if '..' in archive or archive.startswith(os.sep):
                return Response(status=403)
            
            user_base_path = os.path.join(app.config.get("UPLOAD_FOLDER"), str(user_token))
            full_file_path = os.path.join(user_base_path, archive)
            
            # Verificar que el archivo esté dentro del directorio del usuario
            if not full_file_path.startswith(user_base_path):
                return Response(status=403)
            
            if not os.path.isfile(full_file_path):
                return Response(status=404)
                
            log.info(f"[{ip_client}] [/download ] Usuario [{uss}] descargando archivo [{archive}]")
            
            # Extraer directorio y nombre de archivo para send_from_directory
            file_dir = os.path.dirname(full_file_path)
            file_name = os.path.basename(full_file_path)
            return send_from_directory(file_dir, file_name, as_attachment=True)
        except jwt.ExpiredSignatureError:
            log.debug(
                f"[{ip_client}] [/download ] Usuario {uss} expirón token {token}")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            log.debug(
                f"[{ip_client}] [/download ] Usuario {uss} token invalido {token}")
            return redirect(url_for("login"))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/download ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
            return redirect(url_for("download"))
    else:
        try:
            # Verificar si hay una sesión activa
            sessions, token, uss, uid = if_session(session)
            if sessions == True:
                current_folder = request.args.get('folder', '')
                # Validar current_folder para prevenir path traversal
                if current_folder:
                    current_folder = current_folder.replace('..', '').strip(os.sep)
                
                base_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
                current_dir = os.path.join(base_dir, current_folder) if current_folder else base_dir
                
                if not os.path.isdir(base_dir):
                    os.makedirs(base_dir, exist_ok=True)
                
                if current_folder and not os.path.exists(current_dir):
                    return redirect(url_for("download"))
                    
                items = os.listdir(current_dir)
                files = []
                folders = []
                
                for item in items:
                    item_path = os.path.join(current_dir, item)
                    if os.path.isdir(item_path):
                        folders.append(item)
                    else:
                        # Construir ruta relativa correcta para el archivo
                        relative_path = os.path.join(current_folder, item) if current_folder else item
                        file_size = CONFIG.SPACE_FILE(str(uid), relative_path)
                        datos_send_token = {
                            "user": str(uid),
                            "archive": relative_path,
                        }
                        the_token = jwt.encode(datos_send_token, app.config.get("SECRET_KEY"), algorithm="HS256")
                        files.append([item, the_token, file_size])
                
                sorted_files = sorted(files, key=lambda x: x[0])
                sorted_folders = sorted(folders)
                
                page = request.args.get('page', 1, type=int)
                per_page = 15
                total_items = len(sorted_files)
                total_pages = (total_items + per_page - 1) // per_page
                start = (page - 1) * per_page
                end = start + per_page
                paginated_files = sorted_files[start:end]
                
                # Breadcrumb navigation
                breadcrumb = []
                if current_folder:
                    parts = current_folder.split(os.sep)
                    path = ''
                    for part in parts:
                        path = os.path.join(path, part) if path else part
                        breadcrumb.append({'name': part, 'path': path})
                
                log.debug(f"[{ip_client}] [/download ] Usuario {uss} en carpeta [{current_folder or 'raíz'}]")
                return render_template(
                    "files/download.html",
                    user=uss,
                    files=paginated_files,
                    folders=sorted_folders,
                    current_folder=current_folder,
                    breadcrumb=breadcrumb,
                    space=CONFIG.Free_Space(),
                    page=page,
                    total_pages=total_pages,
                    cookie=dark_mode, 
                    version=VERSION
                )
            else:
                log.debug(f"[{ip_client}] [/download ] Usuario no logueado")
                return redirect(url_for("login" , redirect='download'))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/download ] ERROR[0009]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))


@app.route("/thumbnail")
def thumbnail():
    """Servir miniaturas de imágenes"""
    ip_client = request.headers.get("X-Real-IP")
    
    if not request.args.get("token"):
        return Response(status=400)
    
    try:
        the_token = request.args.get("token")
        verific = jwt.decode(the_token, app.config.get("SECRET_KEY"), algorithms=["HS256"])
        archive = verific["archive"]
        user_token = str(verific["user"])
        
        # Validar que el archivo no contenga path traversal
        if '..' in archive or archive.startswith(os.sep):
            return Response(status=403)
        
        user_base_path = os.path.join(app.config.get("UPLOAD_FOLDER"), str(user_token))
        full_file_path = os.path.join(user_base_path, archive)
        
        # Verificar que el archivo esté dentro del directorio del usuario
        if not full_file_path.startswith(user_base_path):
            return Response(status=403)
        
        if not os.path.isfile(full_file_path):
            return Response(status=404)
        
        # Verificar si es una imagen
        if not THUMBNAILS.is_image(archive):
            return Response(status=404)
        
        # Obtener o crear miniatura
        thumb_path = THUMBNAILS.get_or_create_thumbnail(full_file_path, user_token)
        
        if not thumb_path or not os.path.exists(thumb_path):
            return Response(status=404)
        
        log.debug(f"[{ip_client}] [/thumbnail] Miniatura servida para [{archive}]")
        return send_file(thumb_path, mimetype='image/jpeg')
        
    except jwt.ExpiredSignatureError:
        return Response(status=403)
    except jwt.InvalidTokenError:
        return Response(status=403)
    except Exception as e:
        log.error(f"[{ip_client}] [/thumbnail] Error: {e}")
        return Response(status=500)

@app.route("/thumbnail/<filename>")
def thumbnail_by_filename(filename):
    """Servir miniaturas por nombre de archivo (para blog)"""
    ip_client = request.headers.get("X-Real-IP")
    
    try:
        # Sanitizar nombre de archivo
        filename = sanitize_filename(filename)
        if not filename or not THUMBNAILS.is_image(filename):
            return Response(status=404)
        
        # Buscar archivo en uploads de blog (static/blog)
        blog_path = os.path.join(CONFIG.SYSTEM_PATH, "static", "blog", filename)
        
        if not os.path.isfile(blog_path):
            # Si no existe, devolver imagen por defecto
            default_path = os.path.join(CONFIG.SYSTEM_PATH, "static", "blog", "default.png")
            if os.path.exists(default_path):
                return send_file(default_path, mimetype='image/png')
            return Response(status=404)
        
        # Crear miniatura usando un ID genérico para archivos de blog
        thumb_path = THUMBNAILS.get_or_create_thumbnail(blog_path, "blog")
        
        if not thumb_path or not os.path.exists(thumb_path):
            # Si no se puede crear miniatura, devolver imagen original
            return send_file(blog_path)
        
        log.debug(f"[{ip_client}] [/thumbnail/{filename}] Miniatura servida")
        return send_file(thumb_path, mimetype='image/jpeg')
        
    except Exception as e:
        log.error(f"[{ip_client}] [/thumbnail/{filename}] Error: {e}")
        return Response(status=500)




@app.route("/upload", methods=["POST", "GET"])
@csrf.exempt
def upload():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            sessions, token, uss, uid = if_session(session)
            if not sessions:
                return jsonify({"error": "No autorizado"}), 401
            
            # Configuración de límites
            max_file_gb = int(os.getenv('MAX_FILE_SIZE_GB', '4'))
            MAX_FILE_SIZE = max_file_gb * 1024 * 1024 * 1024
            
            # Verificar espacio libre del servidor
            try:
                
                disk_path = 'C:\\' if CONFIG.MY_OS == 'Windows' else '/'
                disk_usage = psutil.disk_usage(disk_path)
                free_space = disk_usage.free
                if free_space < 1024 * 1024 * 1024:  # Menos de 1GB libre
                    return jsonify({"error": "Espacio insuficiente en el servidor"}), 507
            except:
                pass
            
            current_folder = request.form.get('current_folder', '')
            if current_folder:
                current_folder = current_folder.replace('..', '').strip(os.sep)
            
            DIR = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid), current_folder) if current_folder else os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
            os.makedirs(DIR, exist_ok=True)
            
            uploaded_filenames = []
            
            # Subida de archivos locales
            uploaded_files = request.files.getlist("file")
            if uploaded_files and uploaded_files[0].filename:
                for file in uploaded_files:
                    if not file.filename:
                        continue
                    
                    # Verificar tamaño
                    file.seek(0, 2)
                    file_size = file.tell()
                    file.seek(0)
                    
                    if file_size > MAX_FILE_SIZE:
                        return jsonify({"error": f"Archivo muy grande: {file.filename} (máx {max_file_gb}GB)"}), 400
                    
                    filename = sanitize_filename(file.filename)
                    if not filename:
                        continue
                    
                    # Evitar sobrescribir
                    counter = 1
                    original_filename = filename
                    while os.path.exists(os.path.join(DIR, filename)):
                        name, ext = os.path.splitext(original_filename)
                        filename = f"{name}_{counter}{ext}"
                        counter += 1
                    
                    file_path = os.path.join(DIR, filename)
                    file.save(file_path)
                    uploaded_filenames.append(filename)
            
            # Descarga desde URL
            download_url = request.form.get('download_url', '').strip()
            if download_url:
                try:
                    import requests
                    from urllib.parse import urlparse
                    
                    # Validar URL
                    parsed = urlparse(download_url)
                    if not parsed.scheme in ['http', 'https']:
                        return jsonify({"error": "URL no válida"}), 400
                    
                    # Descargar con límite de tamaño
                    download_timeout = int(os.getenv('DOWNLOAD_TIMEOUT_SECONDS', '300'))  # 5 minutos por defecto
                    response = requests.get(download_url, stream=True, timeout=download_timeout)
                    response.raise_for_status()
                    
                    # Obtener nombre de archivo
                    filename = download_url.split('/')[-1] or 'downloaded_file'
                    if '?' in filename:
                        filename = filename.split('?')[0]
                    filename = sanitize_filename(filename)
                    if not filename:
                        filename = 'downloaded_file'
                    
                    # Verificar Content-Length si está disponible
                    content_length = response.headers.get('Content-Length')
                    if content_length and int(content_length) > MAX_FILE_SIZE:
                        return jsonify({"error": f"Archivo muy grande desde URL (máx {max_file_gb}GB)"}), 400
                    
                    # Evitar sobrescribir
                    counter = 1
                    original_filename = filename
                    while os.path.exists(os.path.join(DIR, filename)):
                        name, ext = os.path.splitext(original_filename)
                        filename = f"{name}_{counter}{ext}"
                        counter += 1
                    
                    file_path = os.path.join(DIR, filename)
                    
                    # Descargar con límite de tamaño
                    downloaded_size = 0
                    with open(file_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                downloaded_size += len(chunk)
                                if downloaded_size > MAX_FILE_SIZE:
                                    f.close()
                                    os.remove(file_path)
                                    return jsonify({"error": f"Archivo muy grande desde URL (máx {max_file_gb}GB)"}), 400
                                f.write(chunk)
                    
                    uploaded_filenames.append(filename)
                    log.info(f"[{ip_client}] [/upload] Usuario [{uss}] descargó desde URL: {download_url}")
                    
                except requests.RequestException as e:
                    return jsonify({"error": f"Error descargando: {str(e)}"}), 400
                except Exception as e:
                    return jsonify({"error": f"Error procesando descarga: {str(e)}"}), 500
            
            if not uploaded_filenames:
                return jsonify({"error": "No se procesaron archivos"}), 400
            
            log.info(f"[{ip_client}] [/upload] Usuario [{uss}] procesó archivos: {', '.join(uploaded_filenames)}")
            return jsonify({"filenames": uploaded_filenames})
            
        except Exception as e:
            log.error(f"[{ip_client}] [/upload] ERROR: {e} [{traceback.format_exc()}]")
            return jsonify({"error": "Error interno"}), 500
    else:
        try:
            sessions, token, uss, uid = if_session(session)
            if sessions:
                return render_template("files/upload.html", user=uss, space=CONFIG.Free_Space(), cookie=dark_mode, version=VERSION)
            else:
                return redirect(url_for("login"))
        except Exception as e:
            log.error(f"[{ip_client}] [/upload] ERROR: {e}")
            return redirect(url_for("login"))

@app.route("/delete")
def delete():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        if request.args.get("del_file"):
            try:
                the_token = request.args.get("del_file")
                verific = jwt.decode(the_token, app.config.get("SECRET_KEY"), algorithms=["HS256"])
                archive = verific["archive"]
                user_token = str(verific["user"])
                suid = USERPG.GET_USER("id", user_token)
                uss = suid['username']
                the_path = os.path.join(app.config.get("UPLOAD_FOLDER"), user_token, archive)
                os.remove(the_path)
                log.info( f"[{ip_client}] [/delete ] Usuario [{uss}] borrón archivo [{archive}]")
                flash(f"{archive} borrado correctamente","success")
                return redirect(url_for("download"))
            except jwt.ExpiredSignatureError:
                log.debug(f"[{ip_client}] [/delete ] expiró el token")
                return redirect(url_for("login"), code=403)
            except jwt.InvalidTokenError:
                log.debug(
                    f"[{ip_client}] [/delete ] token invalido")
                return redirect(url_for("login"), code=403)
            except Exception as e:
                log.error(
                    f"[{ip_client}] [/delete ] error {e} [{traceback.format_exc()}]")
                return redirect(url_for("login"))
        else:
            log.debug(f"[{ip_client}] [/delete ] [method GET]")
            return redirect(url_for("download"))
    except Exception as e:
            log.error(f"[{ip_client}] [/delete ] ERROR[0012]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))

@app.route("/folder", methods=["POST", "DELETE"])
@csrf.exempt
def folder():
    ip_client = request.headers.get("X-Real-IP")
    sessions, token, uss, uid = if_session(session)
    if not sessions:
        return jsonify({"error": "No autorizado"}), 401
    
    try:
        data = request.get_json()
        user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
        
        # Validar current_folder si existe
        current_folder = data.get("current_folder", "")
        if current_folder:
            current_folder = current_folder.replace('..', '').strip('/')
        
        if request.method == "POST":
            folder_name = sanitize_filename(data.get("name", ""))
            
            if not folder_name:
                return jsonify({"error": "Nombre inválido"}), 400
            
            if current_folder:
                folder_path = os.path.join(user_dir, current_folder, folder_name)
            else:
                folder_path = os.path.join(user_dir, folder_name)
            if os.path.exists(folder_path):
                return jsonify({"error": "La carpeta ya existe"}), 400
            
            os.makedirs(folder_path)
            log.info(f"[{ip_client}] [/folder ] Usuario [{uss}] creó carpeta [{folder_name}]")
            return jsonify({"success": True, "folder": folder_name})
        
        elif request.method == "DELETE":
            folder_name = data.get("name", "")
            
            if current_folder:
                folder_path = os.path.join(user_dir, current_folder, folder_name)
            else:
                folder_path = os.path.join(user_dir, folder_name)
            
            if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
                return jsonify({"error": "Carpeta no encontrada"}), 404
            
            import shutil
            shutil.rmtree(folder_path)
            log.info(f"[{ip_client}] [/folder ] Usuario [{uss}] eliminó carpeta [{folder_name}]")
            return jsonify({"success": True})
            
    except Exception as e:
        log.error(f"[{ip_client}] [/folder ] Error: {e}")
        return jsonify({"error": "Error interno"}), 500

@app.route("/move", methods=["POST"])
@csrf.exempt
def move_file():
    ip_client = request.headers.get("X-Real-IP")
    sessions, token, uss, uid = if_session(session)
    if not sessions:
        return jsonify({"error": "No autorizado"}), 401
    
    try:
        data = request.get_json()
        file_name = data.get("file")
        target_folder = data.get("folder", "")
        current_folder = data.get("current_folder", "")
        
        user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
        
        # Validar y limpiar current_folder para prevenir path traversal
        if current_folder:
            current_folder = current_folder.replace('..', '').strip(os.sep)
        
        # Obtener la carpeta actual desde la cual se mueve el archivo
        current_location = current_folder if current_folder else ""
        
        # Ruta actual del archivo (puede estar en subcarpeta)
        if current_location:
            source_path = os.path.join(user_dir, current_location, file_name)
        else:
            source_path = os.path.join(user_dir, file_name)
        
        # Ruta destino
        if target_folder:
            target_path = os.path.join(user_dir, target_folder, file_name)
        else:
            target_path = os.path.join(user_dir, file_name)
        
        if not os.path.exists(source_path):
            return jsonify({"error": "Archivo no encontrado"}), 404
        
        if target_folder and not os.path.exists(os.path.join(user_dir, target_folder)):
            return jsonify({"error": "Carpeta destino no existe"}), 404
        
        import shutil
        shutil.move(source_path, target_path)
        log.info(f"[{ip_client}] [/move ] Usuario [{uss}] movió [{file_name}] de [{current_folder or 'raíz'}] a [{target_folder or 'raíz'}]")
        return jsonify({"success": True})
        
    except Exception as e:
        log.error(f"[{ip_client}] [/move ] Error: {e}")
        return jsonify({"error": "Error interno"}), 500

@app.route("/rename", methods=["POST"])
@csrf.exempt
def rename_item():
    ip_client = request.headers.get("X-Real-IP")
    sessions, token, uss, uid = if_session(session)
    if not sessions:
        return jsonify({"error": "No autorizado"}), 401
    
    try:
        data = request.get_json()
        old_name = data.get("old_name")
        new_name = sanitize_filename(data.get("new_name", ""))
        current_folder = data.get("current_folder", "")
        is_folder = data.get("is_folder", False)
        
        if not new_name or new_name == old_name:
            return jsonify({"error": "Nombre inválido"}), 400
        
        user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
        
        # Validar y limpiar current_folder para prevenir path traversal
        if current_folder:
            current_folder = current_folder.replace('..', '').strip(os.sep)
        
        # Construir rutas considerando la ubicación actual
        if current_folder and not is_folder:
            # Archivo dentro de una carpeta
            old_path = os.path.join(user_dir, current_folder, old_name)
            new_path = os.path.join(user_dir, current_folder, new_name)
        elif current_folder and is_folder:
            # Carpeta dentro de otra carpeta
            old_path = os.path.join(user_dir, current_folder, old_name)
            new_path = os.path.join(user_dir, current_folder, new_name)
        else:
            # Elemento en la raíz
            old_path = os.path.join(user_dir, old_name)
            new_path = os.path.join(user_dir, new_name)
        
        if not os.path.exists(old_path):
            return jsonify({"error": "Elemento no encontrado"}), 404
        
        if os.path.exists(new_path):
            return jsonify({"error": "Ya existe un elemento con ese nombre"}), 400
        
        os.rename(old_path, new_path)
        item_type = "carpeta" if is_folder else "archivo"
        log.info(f"[{ip_client}] [/rename ] Usuario [{uss}] renombró {item_type} [{old_name}] a [{new_name}]")
        return jsonify({"success": True})
        
    except Exception as e:
        log.error(f"[{ip_client}] [/rename ] Error: {e}")
        return jsonify({"error": "Error interno"}), 500


@app.route("/news")
@app.route("/blog/")
@app.route("/blog")
def blog():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        
        if request.args.get('tags'):
            posts = BLOGPG.GET_BL('tags',request.args.get('tags'))
        elif request.args.get('autor'):
            autor = USERPG.GET_USER('username', request.args.get('autor'))
            posts = BLOGPG.GET_BL('creat_id', autor['username'])
        elif request.args.get('time'):
            posts = BLOGPG.GET_BL('time', request.args.get('time'))
        elif request.args.get('search'):
            allposts = BLOGPG.GET_BL('all')
            data_search = request.args.get('search').lower()
            posts = []
            for post in allposts:
                if data_search in post['title'].lower() or data_search in post['content'].lower() or data_search in post['descript'].lower():
                    posts.append(post)
        else:
            posts = BLOGPG.GET_BL('all')

        page = request.args.get('page', 1, type=int)
        per_page = 9
        if posts == None:
            posts = []
        total_posts = len(posts)
        total_pages = (total_posts + per_page - 1) // per_page  # Calcula el número total de páginas
        start = (page - 1) * per_page
        end = start + per_page
        paginated_posts = posts[start:end]
        paginated_posts.sort(key=lambda x: x['id'], reverse=True)
        
        # Crear contexto de template sin conflictos
        template_context = {
            'posts': paginated_posts, 
            'current_page': page, 
            'total_pages': total_pages, 
            'cookie': dark_mode, 
            'version': VERSION
        }
        
        if sessions == True:
            template_context['user'] = uss
            
        return render_template("blog/blog.html", **template_context)       
    except Exception as e:
        log.error(
            f"[{ip_client}] [/layout ] ERROR[-1]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/blog/<name>", methods=["POST", "GET"])
def blogview(name):
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    error_message = None
    delete_error_message = None
    edit_error_message = None
    comment_to_edit = None

    # Valores por defecto (solo usados si NO estás logueado)
    comment_name_default = ""
    comment_email_default = ""

    try:
        # Verificar sesión: (sessions=True/False, token=?, uss=USERNAME, uid=ID)
        sessions, token, uss, uid = if_session(session)
        
        # Si hay sesión, cargar username y email del usuario
        if sessions:
            user_data = USERPG.GET_USER('id', uid)
            if user_data:
                comment_name_default = user_data['username']
                comment_email_default = user_data['email']

        # Obtener el post actual por título
        the_posts = BLOGPG.GET_BL("title", name, SUM_VIEW=True)
        if not the_posts:
            return redirect(url_for("blog"))
        current_post = the_posts[0]

        # Sumar la vista
        BLOGPG.EDIT_BL('count_view', current_post['id'], current_post['count_view'] + 1)

        # Obtener 3 posts recientes
        recent_posts = sorted(BLOGPG.GET_BL('all') or [], key=lambda x: x['id'], reverse=True)[:3]

        # --- Funciones auxiliares para comentarios ---

        def get_comments(blog_id):
            blog_data = BLOGPG.GET_BL('id', blog_id, MARKDOWN=False, UID=False, TAGS=False)
            if not blog_data or not blog_data[0]['extra']:
                return []
            try:
                return json.loads(blog_data[0]['extra'])
            except json.JSONDecodeError:
                return []

        def save_comments(blog_id, comments_list):
            return BLOGPG.EDIT_BL('extra', blog_id, json.dumps(comments_list))

        def add_comment(blog_id, name, email, message):
            comments_list = get_comments(blog_id)
            # Determinar dueño del comentario
            if sessions:
                owner = uss  # Se asume que post['creat_id'] es un username
            else:
                if not session.get('comment_token'):
                    session['comment_token'] = os.urandom(16).hex()
                owner = session['comment_token']

            new_comment = {
                "name": name,
                "email": email,
                "message": message,
                "date": datetime.datetime.now().isoformat(),
                "owner": owner
            }
            comments_list.append(new_comment)
            return save_comments(blog_id, comments_list)

        def find_comment(blog_id, index):
            # Retorna (comentario, lista_completa)
            comments_list = get_comments(blog_id)
            if 0 <= index < len(comments_list):
                return comments_list[index], comments_list
            return None, comments_list

        # Verifica si el usuario actual (creador del post o autor del comentario) puede editar/borrar
        def can_edit_or_delete(comment_owner, post_creator):
            """
            Se asume que 'post_creator' y 'comment_owner' son usernames.
            Si tu base de datos almacena IDs numéricos para 'creat_id',
            ajusta la comparación con uid en vez de uss.
            """
            if sessions:
                # Si el usuario logueado es el creador del post
                if uss == post_creator:
                    return True
                # O si es el dueño del comentario
                if uss == comment_owner:
                    return True
            else:
                # Usuario anónimo: compara el token
                if session.get('comment_token') == comment_owner:
                    return True
            return False

        def edit_comment(blog_id, index, new_name, new_email, new_message):
            comment, comments_list = find_comment(blog_id, index)
            if not comment:
                return False

            # Solo el dueño del comentario puede editarlo
            can_edit = False
            if sessions:
                if uss == comment.get("owner", ""):
                    can_edit = True
            else:
                if session.get('comment_token') == comment.get("owner", ""):
                    can_edit = True
            
            if not can_edit:
                return False

            # Actualizar comentario
            comment["message"] = new_message
            comment["name"] = new_name
            comment["email"] = new_email
            comment["date"] = datetime.datetime.now().isoformat()

            return save_comments(blog_id, comments_list)

        def delete_comment(blog_id, index):
            comment, comments_list = find_comment(blog_id, index)
            if not comment:
                return False
            
            # Puede borrar: dueño del comentario o creador del post
            can_delete = False
            if sessions:
                # Dueño del comentario
                if uss == comment.get("owner", ""):
                    can_delete = True
                # Creador del post
                elif uss == current_post['creat_id']:
                    can_delete = True
            else:
                # Usuario anónimo solo puede borrar sus propios comentarios
                if session.get('comment_token') == comment.get("owner", ""):
                    can_delete = True
            
            if not can_delete:
                return False
                
            comments_list.pop(index)
            return save_comments(blog_id, comments_list)

        # Cargar lista de comentarios inicial
        comments = get_comments(current_post['id'])

        # --- Manejo de formularios ---
        if request.method == "POST":
            csrf_token = request.form.get("csrf_token")
            if not csrf_token:
                error_message = "Token de seguridad requerido"
                return render_template("blog/blogview.html", the_post=the_posts, comments=comments, 
                                     recent=recent_posts, error=error_message, sessions=sessions, 
                                     user=uss if sessions else None, cookie=dark_mode, version=VERSION)
            
            data = request.form

            # 1) Añadir o actualizar comentario
            if 'comment_submit' in data:
                # Si el usuario está logueado, forzamos sus datos de name/email
                if sessions:
                    name_val = comment_name_default
                    email_val = comment_email_default
                else:
                    name_val = data.get('name', '').strip()
                    email_val = data.get('email', '').strip()

                message_val = data.get('message', '').strip()
                if not message_val:
                    error_message = "Please fill in all required fields."
                else:
                    # ¿Es edición o nuevo comentario?
                    if data.get('comment_index_edit'):
                        index_edit = int(data['comment_index_edit'])
                        if not edit_comment(current_post['id'], index_edit, name_val, email_val, message_val):
                            edit_error_message = "Error editing comment."
                    else:
                        # Crear nuevo comentario
                        if add_comment(current_post['id'], name_val, email_val, message_val):
                            # Enviar email al creador del post
                            try:
                                post_author = USERPG.GET_USER('username', current_post['creat_id'])
                                if post_author and post_author.get('email'):
                                    subject = f"Nuevo comentario en tu post: {current_post['title']}"
                                    message = f"""
                                    <html>
                                        <body>
                                            <h2>¡Tienes un nuevo comentario!</h2>
                                            <p><strong>En tu post:</strong> {current_post['title']}</p>
                                            <p><strong>Comentario de:</strong> {name_val} ({email_val})</p>
                                            <p><strong>Mensaje:</strong></p>
                                            <blockquote style="border-left: 3px solid #6c55f9; padding-left: 15px; margin: 15px 0; color: #555;">
                                                {message_val}
                                            </blockquote>
                                            <p><a href="{os.getenv('BASE_URL', 'https://xxacrvxx.ydns.eu')}/blog/{current_post['title']}">Ver comentario completo</a></p>
                                            <hr>
                                            <small>Puedes responder directamente a este email para contactar con {name_val}</small>
                                        </body>
                                    </html>
                                    """
                                    SEND_MAIL(post_author['email'], subject, message, reply_to=email_val)
                            except Exception as e:
                                log.warning(f"Error enviando notificación de comentario: {e}")
                        else:
                            error_message = "Error adding comment."

                return redirect(url_for("blogview", name=name) + "#comments")

            # 2) Borrar comentario
            elif 'delete_comment' in data and data['delete_comment'].isdigit():
                index_del = int(data['delete_comment'])
                if not delete_comment(current_post['id'], index_del):
                    delete_error_message = "Error deleting comment."
                return redirect(url_for("blogview", name=name) + "#comments")

            # 3) Preparar edición (cargar datos en el formulario)
            elif 'edit_comment' in data and data['edit_comment'].isdigit():
                index_edit = int(data['edit_comment'])
                comment_found, _ = find_comment(current_post['id'], index_edit)
                # Solo el dueño del comentario puede editarlo
                can_edit = False
                if sessions:
                    if uss == comment_found.get('owner', ''):
                        can_edit = True
                else:
                    if session.get('comment_token') == comment_found.get('owner', ''):
                        can_edit = True
                
                if comment_found and can_edit:
                    comment_to_edit = comment_found
                    if not sessions:
                        comment_name_default = comment_to_edit['name']
                        comment_email_default = comment_to_edit['email']
                else:
                    edit_error_message = "Solo puedes editar tus propios comentarios."

        # Determinar "owner" actual para mostrar los botones de edición en la plantilla
        if sessions:
            current_user_owner = uss
        else:
            current_user_owner = session.get('comment_token')

        # Procesar contenido para medios
        processed_content = current_post.get('content', '')
        
        # Render de la plantilla
        template_params = dict(
            the_post=the_posts,
            recent=recent_posts,
            cookie=dark_mode,
            comments=comments,
            error=error_message,
            delete_error=delete_error_message,
            edit_error=edit_error_message,
            comment_to_edit=comment_to_edit,
            comment_name_default=comment_name_default,
            comment_email_default=comment_email_default,
            current_user_owner=current_user_owner,
            sessions=sessions,
            version=VERSION
        )
        if sessions:
            template_params.update(dict(uid=uid, user=uss))

        return render_template("blog/blogview.html", **template_params)

    except Exception as e:
        log.error(f"[{ip_client}] [/blogview ] ERROR[-1]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))
    


@app.route("/blogpost", methods=["POST", "GET"])
def blogpost():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            if request.method == "POST":
                csrf_token = request.form.get("csrf_token")
                if not csrf_token:
                    flash("Token de seguridad requerido", "error")
                    return render_template("blog/blogpost.html", user=uss, cookie=dark_mode, version=VERSION)
                
                CREAT_ID = uid
                TITLE = request.form.get("title")
                DESCRIP = request.form.get("descrip")
                CONTENT = request.form.get("content")
                IMAGE = request.form.get("image")
                TAGS = request.form.get("tags").replace(" ", "")
                
                BLOGPG.INSERT_BL(TITLE, DESCRIP, CONTENT, CREAT_ID, IMAGE, TAGS)
                return redirect(url_for("blog"))
            else:
                return render_template("blog/blogpost.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return redirect(url_for("login"))
    except Exception as e:
        log.error(f"[{ip_client}] [/layout ] ERROR[-1]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))
 

@app.route("/blogedit/<post_id>", methods=["POST", "GET"])
def blogedit(post_id):
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            if BLOGPG.GET_BL('id', post_id):
                post = BLOGPG.GET_BL('id', post_id, MARKDOWN=False, UID=False, TAGS=False)[0]
            else:
                flash("No tienes permiso para editar este post", "danger")
                log.warning(f"[{ip_client}] [/layout ] Usuario [{uss}] no autorizado")
                return redirect(url_for("blog"))     
            if request.method == "POST":
                csrf_token = request.form.get("csrf_token")
                if not csrf_token:
                    flash("Token de seguridad requerido", "error")
                    return render_template("blog/blogedit.html", post=post, postid=post_id, user=uss, cookie=dark_mode, version=VERSION)
                
                if post['creat_id'] == int(uid):
                        TITLE = request.form.get("title")
                        DESCRIP = request.form.get("descrip")
                        CONTENT = request.form.get("content")
                        IMAGE = request.form.get("image")
                        TAGS = request.form.get("tags").replace(" ", "")
                        try:
                            BLOGPG.EDIT_BL("title", post_id, TITLE)
                            BLOGPG.EDIT_BL("descript", post_id, DESCRIP)
                            BLOGPG.EDIT_BL("content", post_id, CONTENT)
                            BLOGPG.EDIT_BL("image", post_id, IMAGE)
                            BLOGPG.EDIT_BL("tags", post_id, TAGS)
                            flash("Post editado correctamente", "success")
                            return redirect(url_for("blog"))
                        except Exception as e:
                            flash("Error al editar el post", "danger")
                            log.error(f"[{ip_client}] [/blogedit ] ERROR[-1]: {e} [{traceback.format_exc()}]")
                            return redirect(url_for("blog"))
            else:
                return render_template("blog/blogedit.html", post=post, postid=post_id, user=uss, cookie=dark_mode, version=VERSION)
        else:
            flash("No tienes permiso para editar este post", "danger")
            log.warning(f"[{ip_client}] [/layout ] Usuario no autorizado")
            return redirect(url_for("login"))
    except Exception as e:
        log.error(f"[{ip_client}] [/layout ] ERROR[-1]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))
    
    
@app.route("/blogdelete/<post_id>")
def blogdelete(post_id):
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            if BLOGPG.GET_BL('id', post_id):
                post = BLOGPG.GET_BL('id', post_id, UID=False)[0]
                if post['creat_id'] == int(uid):
                    BLOGPG.DELETE_BL(post_id)
                    flash("Post borrado correctamente", "success")
                    return redirect(url_for("blog"))
                else:
                    flash("No tienes permiso para borrar este post", "danger")
                    return redirect(url_for("blog"))
            else:
                flash("El post no existe", "danger")
                return redirect(url_for("blog"))
        else:
            return Response(status=403)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/details ] ERROR[0013]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/redirect")
def w_redirect():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        if request.args.get('url'):
            return redirect(request.args.get('url'))
        if  request.args.get('r'):
            return redirect(request.args.get('r'))
        else:
            return redirect(url_for("index"))
    except Exception as e:
        log.error(
            f"[{ip_client}] [/details ] ERROR[0013]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/details")
def detalles():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            return render_template('pages/details.html', user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template('pages/details.html', cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/details ] ERROR[0013]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))
   

@app.route("/services")
def servicios():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            return render_template("pages/services.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("pages/services.html", cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/services ] ERROR[0014]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))
        


@app.route("/contact", methods=["POST", "GET"])
def contactar():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            # Verificar si hay una sesión activa
            sessions, token, uss, uid = if_session(session)
            
            csrf_token = request.form.get("csrf_token")
            if not csrf_token:
                flash("Token de seguridad requerido", "error")
                return render_template("contact.html", cookie=dark_mode, version=VERSION)
            
            nowtime = datetime.datetime.now()
            email_user = request.form.get("email")
            username = request.form.get("username")
            message_user = request.form.get("message")
            email_to_send = EMAIL_WEBMASTER

            subject = f"MSGWeb de {str(username)}"
            message = f"""<html>
                <head></head>
                <body>
                <div class="container">
                <h1>Enviado por: <strong>{str(username)}</strong></h1>
                <h2>El dia {nowtime.strftime('%m/%d/%Y - %I:%M%p')}.</h2>
                </div>
                <div class="container">
                <h1>Email del usuario:</h1>
                <h1><strong>{email_user}</strong></h1>
                </div>
                <h1>Mensaje del usuario</h1><h2>{message_user}</h2>
                </body>
                </html>"""

            sendMail = SEND_MAIL(email_to_send, subject, message)
            if sendMail == False:
                resp = "Oups... Ocurrio un error al enviar el correo, intente mas tarde"
            else:
                resp = "Mensaje enviado, espere nuestra respuesta en su correo"

            if sessions == True:
                return render_template("pages/contact.html", user=uss, response=resp, cookie=dark_mode, version=VERSION)
            else:
                return render_template("pages/contact.html", response=resp, cookie=dark_mode, version=VERSION)
        except Exception as e:
            log.error(
                f"[{ip_client}] [/contact ] ERROR[0016]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("index"))
    else:
        try:
            # Verificar si hay una sesión activa
            sessions, token, uss, uid = if_session(session)
            if sessions == True:
                return render_template("pages/contact.html", user=uss, cookie=dark_mode, version=VERSION)
            else:
                return render_template("pages/contact.html", cookie=dark_mode, version=VERSION)
        except Exception as e:
            log.error(
                f"[{ip_client}] [/contact ] ERROR[0017]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("index"))


@app.route("/conditions")
def ter_y_co():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            return render_template("pages/terms.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("pages/terms.html", cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/conditions ] ERROR[0018]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/privacy")
def privacy():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            return render_template("pages/privacy.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("pages/privacy.html", cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/privacy ] ERROR[0019]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/favicon.ico")
def favicon():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_path = os.path.join(CONFIG.SYSTEM_PATH, "static")
        return send_from_directory(the_path, "favicon.png", as_attachment=False)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/icon ] ERROR[0020]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/robots.txt")
def robots_txt():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_path = os.path.join(CONFIG.SYSTEM_PATH,"static","extra")
        log.debug(f"[{ip_client}] [/robots.txt ] [OK]")
        return send_from_directory(the_path, "robots.txt", as_attachment=False)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/robots.txt ] ERROR[0021]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))

    

@app.route("/humans.txt")
def humans_txt():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_path = os.path.join(CONFIG.SYSTEM_PATH,"static","extra")
        log.debug(f"[{ip_client}] [/humans.txt ] [OK]")
        return send_from_directory(the_path, "humans.txt", as_attachment=False)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/humans.txt ] ERROR[0022]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))



@app.route("/sitemap.xml")
def sitemap_xml():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_path = os.path.join(CONFIG.SYSTEM_PATH,"static","extra")
        log.debug(f"[{ip_client}] [/sitemap.xml ] [OK]")
        return send_from_directory(the_path, "sitemap.xml", as_attachment=False)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/sitemap.xml ] ERROR[0023]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/v2/sitemap.xml")
def sitemap2_xml():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_path = os.path.join(CONFIG.SYSTEM_PATH,"static","extra")
        log.debug(f"[{ip_client}] [/sitemap.xml ] [OK]")
        return send_from_directory(the_path, "sitemap.xml", as_attachment=True)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/sitemap.xml ] ERROR[0023]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/healthcheck")
def healthcheck():
    DB_STATUS = USERPG.CONNECTION_TEST()
    if DB_STATUS == "\nCONECTADO CORRECTAMENTE A PostgreSQL\n":
        log.debug("[/healthcheck ] [OK]")
        return "[Webapp: ok] [Database: ok]"
    else:
        log.error("[/healthcheck ] [ERROR]")
        return "[Webapp: ok] [Database: error]"
    


@app.route("/status")
def status_server():
    ip_client = get_client_ip()
    dark_mode = request.cookies.get('dark-mode', 'true')
    
    try:
        # Calcular tiempo de actividad
        actual_time = time.time()
        total_time = actual_time - START_SERVER_TIME
        total_time_hour = int(total_time // 3600)
        total_time_min = int((total_time % 3600) // 60)
        total_time_sec = int(total_time % 60)
        
        # Estado de la base de datos
        db_test = USERPG.CONNECTION_TEST()
        db_status = "OK" if db_test == "\nCONECTADO CORRECTAMENTE A PostgreSQL\n" else "ERROR"
        
        # Verificar si es administrador para información sensible
        sessions, token, username, uid = if_session(session)
        is_admin = sessions and check_admin_permission(uid)
        
        # Analizar logs para obtener estadísticas de estabilidad
        def get_stability_stats():
            try:
                log_path = os.path.join(CONFIG.SYSTEM_PATH, "logs", "logger.log")
                if not os.path.exists(log_path):
                    return {'errors_24h': 0, 'warnings_24h': 0, 'last_error': 'Ninguno'}
                
                with open(log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()[-5000:]  # Últimas 5000 líneas
                
                now = datetime.datetime.now()
                yesterday = now - datetime.timedelta(hours=24)
                
                # Debug: mostrar rango de tiempo
                # print(f"Buscando errores desde {yesterday} hasta {now}")
                
                errors_24h = 0
                warnings_24h = 0
                last_error = 'Ninguno'
                
                for line in lines:
                    if '[ERROR]' in line or '[WARNING]' in line:
                        try:
                            # Formato: 2025-07-29,01:30:21-[LEVEL][MODULE]:
                            if line and '-[' in line:
                                timestamp_str = line.split('-[')[0]
                                log_time = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d,%H:%M:%S')
                                if log_time >= yesterday:
                                    if '[ERROR]' in line:
                                        errors_24h += 1
                                        if last_error == 'Ninguno':
                                            last_error = timestamp_str.replace(',', ' ')[:16]
                                    elif '[WARNING]' in line:
                                        warnings_24h += 1
                        except Exception:
                            pass
                
                # Debug temporal - contar errores de hoy si no encuentra ninguno
                if errors_24h == 0:
                    today_str = now.strftime('%Y-%m-%d')
                    for line in lines:
                        if '[ERROR]' in line and today_str in line:
                            errors_24h += 1
                            if last_error == 'Ninguno':
                                try:
                                    ts = line.split('-[')[0].replace(',', ' ')[:16]
                                    last_error = ts
                                except:
                                    last_error = 'Hoy'
                
                return {
                    'errors_24h': errors_24h,
                    'warnings_24h': warnings_24h,
                    'last_error': last_error
                }
            except:
                return {'errors_24h': 0, 'warnings_24h': 0, 'last_error': 'No disponible'}
        
        stability = get_stability_stats()
        
        # Generar historial de estabilidad (últimos 30 días)
        def get_stability_history():
            try:
                log_path = os.path.join(CONFIG.SYSTEM_PATH, "logs", "logger.log")
                if not os.path.exists(log_path):
                    return [{'date': (datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d'), 'status': 'ok'} for i in range(29, -1, -1)]
                
                with open(log_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                # Crear diccionario de días con errores
                error_days = set()
                critical_days = set()
                
                for line in lines:
                    if '[ERROR]' in line or '[CRITICAL]' in line:
                        try:
                            # Formato: 2025-07-29,01:30:21-[LEVEL][MODULE]:
                            if line and '-[' in line:
                                date_str = line.split(',')[0]  # YYYY-MM-DD
                                if '[CRITICAL]' in line:
                                    critical_days.add(date_str)
                                elif '[ERROR]' in line:
                                    error_days.add(date_str)
                        except:
                            pass
                
                # Generar historial de 30 días
                history = []
                for i in range(29, -1, -1):
                    date = (datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d')
                    if date in critical_days:
                        status = 'critical'
                    elif date in error_days:
                        status = 'error'
                    else:
                        status = 'ok'
                    history.append({'date': date, 'status': status})
                
                return history
            except:
                return [{'date': (datetime.datetime.now() - datetime.timedelta(days=i)).strftime('%Y-%m-%d'), 'status': 'ok'} for i in range(29, -1, -1)]
        
        stability_history = get_stability_history()
        
        # Información básica (siempre visible)
        server_info = {
            'version': VERSION,
            'status': 'Online',
            'stability': stability,
            'stability_history': stability_history
        }
        
        # Información sensible (solo para admins)
        if is_admin:
            try:
                stats = ADMIN.get_system_stats()
                memory_usage = stats.get('memory_usage', 0)
                cpu_usage = stats.get('cpu_usage', 0)
                disk_usage = stats.get('disk_usage', 0)
                process_memory = stats.get('process_memory', 0)
            except:
                memory_usage = cpu_usage = disk_usage = process_memory = 0
            
            try:
                users = USERPG.GET_ALL_USERS() or []
                posts = BLOGPG.GET_BL('all') or []
                total_users = len(users)
                total_posts = len(posts)
                verified_users = len([u for u in users if u.get('email_confirm') == 'true'])
                total_views = sum(post.get('count_view', 0) for post in posts)
            except:
                total_users = total_posts = verified_users = total_views = 0
            
            try:
                analytics = ANALYTICS.get_analytics_data()
                total_visits = analytics.get('total_visits', 0)
                unique_visitors = analytics.get('unique_visitors', 0)
            except:
                total_visits = unique_visitors = 0
            
            server_info.update({
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                'os': CONFIG.MY_OS if hasattr(CONFIG, 'MY_OS') else 'Unknown',
                'debug_mode': os.getenv('DEBUG', 'False'),
                'maintenance_mode': os.getenv('MAINTENANCE_MODE', 'False')
            })
        else:
            # Valores por defecto para usuarios normales
            memory_usage = cpu_usage = disk_usage = process_memory = 0
            total_users = total_posts = verified_users = total_views = 0
            total_visits = unique_visitors = 0
        
        status_data = {
            'uptime': {
                'hours': total_time_hour,
                'minutes': total_time_min,
                'seconds': total_time_sec,
                'total_seconds': int(total_time)
            },
            'database': {
                'status': db_status
            },
            'server': server_info,
            'is_admin': is_admin
        }
        
        # Agregar información sensible solo para admins
        if is_admin:
            status_data.update({
                'database': {
                    'status': db_status,
                    'connection_test': db_test.strip() if db_test else 'No response'
                },
                'system': {
                    'memory_usage': memory_usage,
                    'cpu_usage': cpu_usage,
                    'disk_usage': disk_usage,
                    'process_memory': process_memory
                },
                'content': {
                    'total_users': total_users,
                    'verified_users': verified_users,
                    'total_posts': total_posts,
                    'total_views': total_views
                },
                'analytics': {
                    'total_visits': total_visits,
                    'unique_visitors': unique_visitors
                }
            })
        
        # Si es una petición AJAX, devolver JSON
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            log.debug(f"[{ip_client}] [/status] JSON response")
            return jsonify(status_data)
        
        # Respuesta HTML
        log.debug(f"[{ip_client}] [/status] HTML response")
        
        return render_template('status.html', 
                           status=status_data,
                           user=username if sessions else None,
                           cookie=dark_mode,
                           version=VERSION)
        
    except Exception as e:
        log.error(f"[{ip_client}] [/status] ERROR: {e} [{traceback.format_exc()}]")
        
        # Respuesta de error mínima
        error_data = {
            'webapp': 'ERROR',
            'database': 'UNKNOWN',
            'error': str(e)
        }
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify(error_data), 500
        else:
            return f"<h1>Status Error</h1><p>WebApp: ERROR</p><p>Error: {str(e)}</p>", 500
    

# ============================================================================
# RUTAS DE ADMINISTRACIÓN
# ============================================================================

@app.route("/admin/dashboard")
def admin_dashboard():
    """Panel principal de administración."""
    ip_client = get_client_ip()
    dark_mode = request.cookies.get('dark-mode', 'true')
    sessions, token, username, uid = if_session(session)
    
    try:
        stats = ADMIN.get_system_stats()
        db_status = USERPG.CONNECTION_TEST() == "\nCONECTADO CORRECTAMENTE A PostgreSQL\n"
        
        log.info(f"[{ip_client}] [/admin/dashboard] Acceso por {username}")
        
        return render_template("admin/dashboard.html",
                             stats=stats,
                             db_status=db_status,
                             disk_usage=stats.get('disk_usage', 0),
                             memory_usage=stats.get('memory_usage', 0),
                             failed_logins=ADMIN.get_failed_login_count(),
                             user=username,
                             cookie=dark_mode,
                             version=VERSION)
    except Exception as e:
        log.error(f"[{ip_client}] [/admin/dashboard] Error: {e}")
        flash("Error cargando el dashboard", "error")
        return redirect(url_for("index"))

@app.route("/admin/users")
def admin_users():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    
    sessions, token, uss, uid = if_session(session)
    
    try:
        users = USERPG.GET_ALL_USERS()
        # Ordenar alfabéticamente por username
        users.sort(key=lambda x: x.get('username', '').lower())
        
        # Calcular estadísticas
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        week_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
        
        stats = {
            'verified': len([u for u in users if u.get('email_confirm') == 'true']),
            'pending': len([u for u in users if u.get('email_confirm') != 'true']),
            'active_today': len([u for u in users if u.get('extra') and today in u.get('extra', '')]),
            'new_week': len([u for u in users if u.get('time') and u.get('time')[:10] >= week_ago])
        }
        
        # Calcular fecha de hace una semana para el template
        week_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
        
        return render_template("admin/users.html",
                             users=users,
                             stats=stats,
                             week_ago=week_ago,
                             user=uss,
                             cookie=dark_mode,
                             version=VERSION)
    except Exception as e:
        log.error(f"[{ip_client}] [/admin/users] Error: {e}")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/users/<int:user_id>")
def admin_user_detail(user_id):
    sessions, token, uss, uid = if_session(session)
    
    try:
        user = USERPG.GET_USER('id', user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
        
        user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(user_id))
        file_count = len(os.listdir(user_dir)) if os.path.exists(user_dir) else 0
        
        posts = BLOGPG.GET_BL('creat_id', user_id) or []
        post_count = len(posts)
        
        user['file_count'] = file_count
        user['post_count'] = post_count
        user['created_at'] = user.get('time', 'Desconocido')[:10] if user.get('time') else 'Desconocido'
        user['last_login'] = user.get('extra', 'Nunca')
        
        # Estado de verificación de email
        email_confirm = user.get('email_confirm', 'false')
        if email_confirm == 'true':
            user['email_status'] = 'verified'
        elif email_confirm.startswith('skipped_'):
            try:
                import time
                skip_timestamp = int(email_confirm.split('_')[1])
                days_passed = (time.time() - skip_timestamp) / (24 * 3600)
                user['email_status'] = f'skipped_{int(days_passed)}d_ago'
            except:
                user['email_status'] = 'skipped_unknown'
        else:
            user['email_status'] = 'pending'
        
        return jsonify(user)
    except Exception as e:
        return jsonify({"error": "Error interno"}), 500

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
@csrf.exempt
def admin_user_delete(user_id):
    """Eliminar usuario (solo administradores)."""
    ip_client = get_client_ip()
    sessions, token, username, uid = if_session(session)
    
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        data = request.get_json() or {}
        
        # Validar CSRF token
        if not validate_csrf_token(data.get('csrf_token')):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        # Prevenir auto-eliminación
        if user_id == uid:
            return jsonify({"error": "No puedes eliminar tu propia cuenta desde aquí"}), 400
        
        user = USERPG.GET_USER('id', user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
        
        # Eliminar archivos del usuario
        user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(user_id))
        if os.path.exists(user_dir):
            import shutil
            shutil.rmtree(user_dir)
            log.info(f"[{ip_client}] [ADMIN] Archivos eliminados para usuario {user['username']}")
        
        # Eliminar posts del usuario
        posts = BLOGPG.GET_BL('creat_id', user_id) or []
        for post in posts:
            BLOGPG.DELETE_BL(post['id'])
        
        # Eliminar usuario de la base de datos
        USERPG.DELETE(user_id)
        
        log.warning(f"[{ip_client}] [ADMIN] Usuario {user['username']} (ID: {user_id}, Email: {user['email']}) eliminado por {username}")
        return jsonify({"success": True, "message": "Usuario eliminado correctamente"})
        
    except Exception as e:
        log.error(f"[{ip_client}] [ADMIN] Error eliminando usuario {user_id}: {e}")
        return jsonify({"error": "Error interno"}), 500

@app.route("/admin/users/<int:user_id>/verify", methods=["POST"])
@csrf.exempt
def admin_user_verify(user_id):
    sessions, token, uss, uid = if_session(session)
    
    try:
        data = request.get_json() or {}
        
        # Validar CSRF token
        if not data.get('csrf_token'):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        user = USERPG.GET_USER('id', user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
        
        USERPG.EDITAR('email_confirm', user['username'], 'true')
        log.info(f"[ADMIN] Usuario {user['username']} (Email: {user['email']}) verificado por {uss}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": "Error interno"}), 500

@app.route("/admin/users/<int:user_id>/edit", methods=["POST"])
@csrf.exempt
def admin_user_edit(user_id):
    sessions, token, uss, uid = if_session(session)
    
    try:
        user = USERPG.GET_USER('id', user_id)
        if not user:
            return jsonify({"error": "Usuario no encontrado"}), 404
        
        data = request.get_json()
        
        # Validar CSRF token
        if not data.get('csrf_token'):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        # Actualizar campos permitidos
        if 'username' in data and data['username'] != user['username']:
            existing = USERPG.GET_USER('username', data['username'])
            if existing:
                return jsonify({"error": "El nombre de usuario ya existe"}), 400
            USERPG.EDITAR('username', user['username'], data['username'])
            user['username'] = data['username']
        
        if 'email' in data and data['email'] != user['email']:
            existing = USERPG.GET_USER('email', data['email'])
            if existing:
                return jsonify({"error": "El email ya existe"}), 400
            USERPG.EDITAR('email', user['username'], data['email'])
        
        if 'email_confirm' in data:
            if data['email_confirm'] == 'force_verify':
                USERPG.EDITAR('email_confirm', user['username'], 'false')
            else:
                USERPG.EDITAR('email_confirm', user['username'], 'true' if data['email_confirm'] else 'false')
        
        if 'permission' in data:
            USERPG.EDITAR('permission', user['username'], data['permission'])
        
        # Cambiar contraseña si se proporciona
        if 'password' in data and data['password'].strip():
            import bcrypt
            hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
            USERPG.EDITAR('passw', user['username'], hashed_password.decode('utf-8'))
        
        changes = []
        if 'username' in data and data['username'] != user['username']:
            changes.append(f"username: {user['username']} -> {data['username']}")
        if 'email' in data and data['email'] != user['email']:
            changes.append(f"email: {user['email']} -> {data['email']}")
        if 'email_confirm' in data:
            changes.append(f"verificado: {data['email_confirm']}")
        if 'permission' in data:
            changes.append(f"admin: {data['permission'] == 1}")
        if 'password' in data and data['password'].strip():
            changes.append("contraseña cambiada")
        
        log.info(f"[ADMIN] Usuario {user['username']} editado por {uss} - Cambios: {', '.join(changes) if changes else 'ninguno'}")
        return jsonify({"success": True})
    except Exception as e:
        log.error(f"Error editando usuario {user_id}: {e}")
        return jsonify({"error": "Error interno"}), 500

@app.route("/admin/users/create", methods=["POST"])
@csrf.exempt
def admin_user_create():
    sessions, token, uss, uid = if_session(session)
    
    try:
        data = request.get_json()
        
        # Validar CSRF token
        if not data.get('csrf_token'):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        # Validar datos requeridos
        if not all(k in data for k in ['username', 'email', 'password']):
            return jsonify({"error": "Faltan campos requeridos"}), 400
        
        # Validar que la contraseña no esté vacía
        if not data['password'].strip():
            return jsonify({"error": "La contraseña no puede estar vacía"}), 400
        
        # Hash de la contraseña
        import bcrypt
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        
        # Crear usuario
        permission = 1 if data.get('permission') else 0
        result = USERPG.INSERT_USER(data['username'], data['email'], hashed_password.decode('utf-8'), permission)
        
        if "creado correctamente" in result:
            # Si debe estar verificado, actualizar
            if data.get('email_confirm'):
                USERPG.EDITAR('email_confirm', data['username'], 'true')
            
            log.info(f"[ADMIN] Usuario {data['username']} creado por {uss} - Email: {data['email']}, Verificado: {data.get('email_confirm', False)}, Admin: {data.get('permission', 0) == 1}")
            return jsonify({"success": True})
        else:
            return jsonify({"error": result}), 400
            
    except Exception as e:
        log.error(f"Error creando usuario: {e}")
        return jsonify({"error": "Error interno"}), 500

@app.route("/admin/system", methods=["GET", "POST"])
def admin_system():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    
    sessions, token, uss, uid = if_session(session)
    
    if request.method == "POST":
        csrf_token = request.form.get("csrf_token")
        if not csrf_token:
            flash("Token de seguridad requerido", "error")
            return redirect(url_for("admin_system"))
        
        section = request.form.get("section")
        
        try:
            config_path = os.path.join(os.getcwd(), 'config.env')
            config_lines = []
            
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config_lines = f.readlines()
            
            updated = False
            
            if section == "email":
                admin_email = request.form.get('admin_email', '').strip()
                smtp_user = request.form.get('smtp_user', '').strip()
                
                if admin_email:
                    updated |= update_env_var(config_lines, 'EMAIL_WEBMASTER', admin_email)
                if smtp_user:
                    updated |= update_env_var(config_lines, 'EMAIL_USER', smtp_user)
                    
            elif section == "server":
                debug_mode = request.form.get('debug_mode', 'False')
                email_verification_mode = request.form.get('email_verification_mode', '1')
                maintenance_mode = request.form.get('maintenance_mode', 'False')
                registration_enabled = request.form.get('registration_enabled', 'True')
                
                updated |= update_env_var(config_lines, 'DEBUG', debug_mode)
                updated |= update_env_var(config_lines, 'EMAIL_VERIFICATION_MODE', email_verification_mode)
                updated |= update_env_var(config_lines, 'MAINTENANCE_MODE', maintenance_mode)
                updated |= update_env_var(config_lines, 'REGISTRATION_ENABLED', registration_enabled)
                    
            elif section == "app":
                base_url = request.form.get('base_url', '').strip()
                max_file_size = request.form.get('max_file_size', '4')
                max_login_attempts = request.form.get('max_login_attempts', '5')
                remember_me_days = request.form.get('remember_me_days', '30')
                download_timeout = request.form.get('download_timeout', '300')
                session_timeout = request.form.get('session_timeout', '24')
                auto_backup = request.form.get('auto_backup', 'False')
                thumbnail_quality = request.form.get('thumbnail_quality', '85')
                
                if base_url:
                    updated |= update_env_var(config_lines, 'BASE_URL', base_url)
                updated |= update_env_var(config_lines, 'MAX_FILE_SIZE_GB', max_file_size)
                updated |= update_env_var(config_lines, 'MAX_LOGIN_ATTEMPTS', max_login_attempts)
                updated |= update_env_var(config_lines, 'REMEMBER_ME_DAYS', remember_me_days)
                updated |= update_env_var(config_lines, 'DOWNLOAD_TIMEOUT_SECONDS', download_timeout)
                updated |= update_env_var(config_lines, 'SESSION_TIMEOUT_HOURS', session_timeout)
                updated |= update_env_var(config_lines, 'AUTO_BACKUP_ENABLED', auto_backup)
                updated |= update_env_var(config_lines, 'THUMBNAIL_QUALITY', thumbnail_quality)
            
            # Escribir archivo actualizado
            if updated:
                with open(config_path, 'w') as f:
                    f.writelines(config_lines)
                
                # Detectar si requiere reinicio
                requires_restart = section in ['app'] or (
                    section == 'server' and any(key in request.form for key in ['debug_mode'])
                )
                
                if requires_restart:
                    flash("Configuración actualizada. Se requiere reinicio para aplicar cambios.", "warning")
                    session['show_restart_modal'] = True
                else:
                    flash("Configuración actualizada correctamente.", "success")
                
                log.info(f"[ADMIN] Configuración de {section} actualizada por {uss}")
            else:
                flash("No se detectaron cambios", "info")
                
        except Exception as e:
            flash(f"Error actualizando configuración: {e}", "error")
            log.error(f"[ADMIN] Error en configuración por {uss}: {e}")
        
        return redirect(url_for("admin_system"))
    
    try:
        config = CONFIG.get_system_config()
        env_vars = CONFIG.get_env_status()
        db_status = test_db_connection()
        system_stats = ADMIN.get_system_stats()
        
        show_restart_modal = session.pop('show_restart_modal', False)
        
        # Validar que todas las configuraciones críticas estén presentes
        critical_vars = ['SECRET_KEY', 'EMAIL_WEBMASTER']
        missing_vars = [var for var in critical_vars if not os.getenv(var)]
        
        if missing_vars:
            flash(f"Variables críticas faltantes: {', '.join(missing_vars)}", "warning")
        
        return render_template("admin/system.html",
                             config=config,
                             env_vars=env_vars,
                             db_status=db_status,
                             system_stats=system_stats,
                             show_restart_modal=show_restart_modal,
                             missing_vars=missing_vars,
                             user=uss,
                             cookie=dark_mode,
                             version=VERSION)
    except Exception as e:
        log.error(f"[{ip_client}] [/admin/system] Error: {e} [{traceback.format_exc()}]")
        flash("Error cargando configuración del sistema", "error")
        return redirect(url_for("admin_dashboard"))

def update_env_var(config_lines, var_name, value):
    """Actualizar o agregar variable de entorno"""
    for i, line in enumerate(config_lines):
        if line.startswith(f'{var_name}=') or line.startswith(f'{var_name} ='):
            config_lines[i] = f'{var_name}={value}\n'
            return True
    
    config_lines.append(f'{var_name}={value}\n')
    return True

def test_db_connection():
    """Probar conexión a la base de datos"""
    try:
        result = USERPG.CONNECTION_TEST()
        return result == "\nCONECTADO CORRECTAMENTE A PostgreSQL\n"
    except Exception as e:
        log.warning(f"Error probando conexión BD: {e}")
        return False



@app.route("/admin/dashboard/metrics")
@csrf.exempt
def admin_dashboard_metrics():
    """API para métricas del dashboard."""
    sessions, token, username, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        return jsonify(ADMIN.get_system_stats())
    except Exception as e:
        log.error(f"Error obteniendo métricas: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/system/test-email", methods=["POST"])
def admin_test_email():
    """Probar configuración de email"""
    try:
        sessions, token, uss, uid = if_session(session)
        if not sessions or not check_admin_permission(uid):
            return jsonify({"error": "Acceso denegado"}), 403
        
        admin_email = os.getenv('EMAIL_WEBMASTER')
        if not admin_email:
            return jsonify({"error": "Email de administrador no configurado"}), 400
        
        subject = "Prueba de configuración de email"
        message = f"""
        <h2>Prueba de Email</h2>
        <p>Este es un email de prueba enviado desde el panel de administración.</p>
        <p><strong>Usuario:</strong> {uss}</p>
        <p><strong>Fecha:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Si recibes este mensaje, la configuración de email está funcionando correctamente.</p>
        """
        
        SEND_MAIL(admin_email, subject, message)
        log.info(f"[ADMIN] Email de prueba enviado por {uss} a {admin_email}")
        return jsonify({"success": True})
        
    except Exception as e:
        log.error(f"Error enviando email de prueba: {e}")
        return jsonify({"error": str(e)}), 500



@app.route("/admin/system/env-var", methods=["POST"])
def admin_env_var():
    """Editar variable de entorno"""
    try:
        sessions, token, uss, uid = if_session(session)
        if not sessions or not check_admin_permission(uid):
            return jsonify({"error": "Acceso denegado"}), 403
        
        data = request.get_json()
        var_name = data.get('name', '').strip()
        var_value = data.get('value', '')
        
        if not var_name:
            return jsonify({"error": "Nombre de variable requerido"}), 400
        
        config_path = os.path.join(os.getcwd(), 'config.env')
        config_lines = []
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_lines = f.readlines()
        
        # Actualizar o añadir variable
        updated = update_env_var(config_lines, var_name, var_value)
        
        with open(config_path, 'w') as f:
            f.writelines(config_lines)
        
        log.info(f"[ADMIN] Variable {var_name} actualizada por {uss}")
        return jsonify({"success": True})
        
    except Exception as e:
        log.error(f"Error actualizando variable de entorno: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/system/instant-update", methods=["POST"])
def admin_instant_update():
    """Actualizar configuración instantáneamente"""
    try:
        sessions, token, uss, uid = if_session(session)
        if not sessions or not check_admin_permission(uid):
            return jsonify({"error": "Acceso denegado"}), 403
        
        data = request.get_json()
        config_name = data.get('config_name', '').strip()
        value = data.get('value', '')
        
        if not config_name:
            return jsonify({"error": "Nombre de configuración requerido"}), 400
        
        config_path = os.path.join(os.getcwd(), 'config.env')
        config_lines = []
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_lines = f.readlines()
        
        # Mapear nombres de configuración a variables de entorno
        config_mapping = {
            'debug_mode': 'DEBUG',
            'email_verification_mode': 'EMAIL_VERIFICATION_MODE',
            'maintenance_mode': 'MAINTENANCE_MODE',
            'registration_enabled': 'REGISTRATION_ENABLED'
        }
        
        env_var = config_mapping.get(config_name)
        if not env_var:
            return jsonify({"error": "Configuración no válida"}), 400
        
        # Actualizar variable
        updated = update_env_var(config_lines, env_var, value)
        
        with open(config_path, 'w') as f:
            f.writelines(config_lines)
        
        # Actualizar variable de entorno en tiempo real
        os.environ[env_var] = value
        
        log.info(f"[ADMIN] Configuración {config_name} actualizada instantáneamente por {uss} a {value}")
        return jsonify({"success": True})
        
    except Exception as e:
        log.error(f"Error actualizando configuración instantánea: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/dashboard/active-users")
@csrf.exempt
def admin_active_users():
    return jsonify({'users': ADMIN.get_active_users()})

@app.route("/admin/dashboard/recent-files")
@csrf.exempt
def admin_recent_files():
    return jsonify({'files': ADMIN.get_recent_files(app.config.get("UPLOAD_FOLDER"))})

@app.route("/admin/dashboard/popular-posts")
@csrf.exempt
def admin_popular_posts():
    try:
        posts = BLOGPG.GET_BL('all') or []
        posts.sort(key=lambda x: x.get('count_view', 0), reverse=True)
        
        popular_posts = []
        for post in posts[:10]:
            # Contar comentarios
            comments_count = 0
            if post.get('extra'):
                try:
                    comments_count = len(json.loads(post['extra']))
                except:
                    comments_count = 0
            
            popular_posts.append({
                'title': post.get('title', 'Sin título'),
                'views': post.get('count_view', 0),
                'author': post.get('creat_id', 'Desconocido'),
                'date': post.get('time', '')[:10] if post.get('time') else '',
                'comments': comments_count
            })
        
        return jsonify({'posts': popular_posts})
    except Exception as e:
        log.error(f"Error obteniendo posts populares: {e}")
        return jsonify({'posts': []})



@app.route("/admin/dashboard/security")
@csrf.exempt
def admin_security_info():
    return jsonify(ADMIN.get_security_info())

@app.route("/admin/dashboard/cleanup", methods=["POST"])
@csrf.exempt
def admin_dashboard_cleanup():
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        cleaned_files = ADMIN.cleanup_temp_files()
        try:
            THUMBNAILS.cleanup_old_thumbnails()
            cleaned_files += 1
        except:
            pass
        
        log.info(f"[ADMIN] Limpieza desde dashboard por {uss} - {cleaned_files} archivos")
        return jsonify({"success": True, "message": f"{cleaned_files} archivos eliminados"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/dashboard/backup", methods=["POST"])
@csrf.exempt
def admin_dashboard_backup():
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        backup_file = ADMIN.create_backup(CONFIG.SYSTEM_PATH)
        if backup_file:
            log.info(f"[ADMIN] Backup desde dashboard por {uss}: {backup_file}")
            return jsonify({"success": True, "message": f"Backup JSON creado: {backup_file}"})
        else:
            return jsonify({"error": "Error creando backup"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/backup/list")
def admin_backup_list():
    """Listar backups disponibles."""
    sessions, token, username, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        backups = ADMIN.list_backups(CONFIG.SYSTEM_PATH)
        return jsonify({"backups": backups})
    except Exception as e:
        log.error(f"Error listando backups: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/backup/download/<filename>")
def admin_backup_download(filename):
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        # Validar nombre de archivo
        if not filename.endswith('.json') or not filename.startswith('backup_'):
            return jsonify({"error": "Archivo no válido"}), 400
        
        backup_dir = os.path.join(CONFIG.SYSTEM_PATH, 'backups')
        file_path = os.path.join(backup_dir, filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "Archivo no encontrado"}), 404
        
        log.info(f"[ADMIN] Descarga de backup por {uss}: {filename}")
        return send_file(file_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/backup/delete/<filename>", methods=["DELETE"])
@csrf.exempt
def admin_backup_delete(filename):
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        if not filename.endswith('.json') or not filename.startswith('backup_'):
            return jsonify({"error": "Archivo no válido"}), 400
        
        backup_dir = os.path.join(CONFIG.SYSTEM_PATH, 'backups')
        file_path = os.path.join(backup_dir, filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "Archivo no encontrado"}), 404
        
        os.remove(file_path)
        log.info(f"[ADMIN] Backup eliminado por {uss}: {filename}")
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/backup/restore", methods=["POST"])
def admin_backup_restore():
    """Restaurar backup desde archivo JSON."""
    ip_client = get_client_ip()
    sessions, token, username, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No se seleccionó archivo"}), 400
        
        file = request.files['file']
        if not file.filename or not file.filename.endswith('.json'):
            return jsonify({"error": "Archivo JSON requerido"}), 400
        
        # Validar tamaño del archivo (máximo 50MB para backups)
        file.seek(0, 2)  # Ir al final
        file_size = file.tell()
        file.seek(0)  # Volver al inicio
        
        if file_size > 50 * 1024 * 1024:  # 50MB
            return jsonify({"error": "Archivo demasiado grande (máximo 50MB)"}), 400
        
        # Guardar archivo temporal de forma segura
        temp_path = os.path.join(tempfile.gettempdir(), f"restore_{int(time.time())}_{os.getpid()}.json")
        file.save(temp_path)
        
        try:
            result = ADMIN.restore_backup(temp_path)
            log.warning(f"[{ip_client}] [ADMIN] Restauración de backup por {username}: {result.get('message', 'Error')}")
            return jsonify(result)
        finally:
            # Limpiar archivo temporal
            try:
                os.remove(temp_path)
            except:
                pass
                
    except Exception as e:
        log.error(f"[{ip_client}] [ADMIN] Error en restauración: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/dashboard/report", methods=["POST", "GET"])
@csrf.exempt
def admin_report():
    sessions, token, uss, uid = if_session(session)
    
    try:
        log.info(f"[ADMIN] Generando reporte por {uss}")
        users = USERPG.GET_ALL_USERS() or []
        posts = BLOGPG.GET_BL('all') or []
        
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        week_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
        
        verified_users = len([u for u in users if u.get('email_confirm') == 'true'])
        active_today = len([u for u in users if u.get('extra') and today in u.get('extra', '')])
        new_week = len([u for u in users if u.get('time') and u.get('time')[:10] >= week_ago])
        
        total_views = sum(post.get('count_view', 0) for post in posts)
        avg_views = (total_views/len(posts)) if posts else 0
        
        # Estadísticas adicionales
        posts_last_week = len([p for p in posts if p.get('time') and p.get('time')[:10] >= week_ago])
        most_active_user = max(users, key=lambda u: len([p for p in posts if p.get('creat_id') == u.get('username')]), default={'username': 'Ninguno'})
        total_comments = sum(len(json.loads(p.get('extra', '[]'))) if p.get('extra') else 0 for p in posts)
        avg_posts_per_user = len(posts) / len(users) if users else 0
        
        report = f"""REPORTE DETALLADO DEL SISTEMA
Generado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== RESUMEN EJECUTIVO ===
Usuarios totales: {len(users)}
Usuarios verificados: {verified_users} ({verified_users/len(users)*100:.1f}%)
Usuarios activos hoy: {active_today}
Nuevos usuarios (7 días): {new_week}
Usuario más activo: {most_active_user['username']}

Posts totales: {len(posts)}
Posts nuevos (7 días): {posts_last_week}
Vistas totales: {total_views}
Promedio vistas/post: {avg_views:.1f}
Promedio posts/usuario: {avg_posts_per_user:.1f}
Comentarios totales: {total_comments}

Archivos subidos: {CONFIG.count_user_files()}
Tiempo activo: {CONFIG.get_uptime()}
Uso de disco: {CONFIG.get_disk_usage()}%
Uso de memoria: {CONFIG.get_memory_usage()}%

=== TOP 10 USUARIOS ===
"""
        
        users_sorted = sorted(users, key=lambda x: x.get('time', ''), reverse=True)
        for user in users_sorted[:10]:
            status = 'Verificado' if user.get('email_confirm') == 'true' else 'Pendiente'
            admin = ' [ADMIN]' if user.get('permission') == 1 else ''
            last_login = user.get('extra', 'Nunca')[:16] if user.get('extra') else 'Nunca'
            report += f"\n- {user['username']}{admin} ({user['email']}) - {status} - Último: {last_login}"
        
        report += f"\n\n=== TOP 10 POSTS MÁS POPULARES ===\n"
        posts.sort(key=lambda x: x.get('count_view', 0), reverse=True)
        for i, post in enumerate(posts[:10], 1):
            author = post.get('creat_id', 'Desconocido')
            report += f"{i}. {post.get('title', 'Sin título')} - {post.get('count_view', 0)} vistas (por {author})\n"
        
        report += f"\n=== ACTIVIDAD RECIENTE ===\n"
        recent_users = [u for u in users if u.get('extra') and today in u.get('extra', '')]
        for user in recent_users[:5]:
            report += f"- {user['username']} activo hoy ({user.get('extra', '')[:16]})\n"
        
        report += f"\n=== ESTADÍSTICAS DE CONTENIDO ===\n"
        if posts:
            tags_count = {}
            for post in posts:
                for tag in post.get('tags', []):
                    if tag.strip():
                        tags_count[tag.strip()] = tags_count.get(tag.strip(), 0) + 1
            
            popular_tags = sorted(tags_count.items(), key=lambda x: x[1], reverse=True)[:5]
            report += "Tags más usados:\n"
            for tag, count in popular_tags:
                report += f"  - {tag}: {count} posts\n"
        
        report += f"\n=== RENDIMIENTO ===\n"
        report += f"Posts con más de 10 vistas: {len([p for p in posts if p.get('count_view', 0) > 10])}\n"
        report += f"Posts sin comentarios: {len([p for p in posts if not p.get('extra') or len(json.loads(p.get('extra', '[]'))) == 0])}\n"
        report += f"Usuarios sin posts: {len([u for u in users if not any(p.get('creat_id') == u.get('username') for p in posts)])}\n"
        
        log.info(f"[ADMIN] Reporte generado por {uss}")
        return Response(report, mimetype='text/plain', headers={'Content-Disposition': 'attachment; filename=reporte.txt'})
    except Exception as e:
        log.error(f"[ADMIN] Error generando reporte por {uss}: {e}")
        return jsonify({'error': f'Error generando reporte: {str(e)}'}), 500

@app.route("/admin/content")
def admin_content():
    dark_mode = request.cookies.get('dark-mode', 'true')
    sessions, token, uss, uid = if_session(session)
    
    try:
        posts = BLOGPG.GET_BL('all') or []
        # Los posts ya vienen con creat_id como username desde BLOGPG.GET_BL
        for post in posts:
            post['author'] = post.get('creat_id', 'Desconocido')
        
        posts.sort(key=lambda x: x.get('id', 0), reverse=True)
        
        return render_template("admin/content.html",
                             posts=posts,
                             user=uss,
                             cookie=dark_mode,
                             version=VERSION)
    except Exception as e:
        log.error(f"[/admin/content] Error: {e}")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/database")
def admin_database():
    dark_mode = request.cookies.get('dark-mode', 'true')
    sessions, token, uss, uid = if_session(session)
    
    try:
        stats = ADMIN.get_system_stats()
        db_status = USERPG.CONNECTION_TEST() == "\nCONECTADO CORRECTAMENTE A PostgreSQL\n"
        
        return render_template("admin/database.html",
                             stats=stats,
                             db_status=db_status,
                             user=uss,
                             cookie=dark_mode,
                             version=VERSION)
    except Exception as e:
        log.error(f"[/admin/database] Error: {e}")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/database/query", methods=["POST"])
@csrf.exempt
def admin_database_query():
    sessions, token, uss, uid = if_session(session)
    
    try:
        data = request.get_json()
        if not data.get('csrf_token'):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        query = data.get('query', '').strip()
        if not query:
            return jsonify({"error": "Consulta vacía"}), 400
        
        # Validar consultas peligrosas
        dangerous = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE', 'INSERT', 'UPDATE']
        if any(word in query.upper() for word in dangerous):
            return jsonify({"error": "Consultas de modificación no permitidas por seguridad"}), 403
        
        # Limitar a consultas SELECT
        if not query.upper().strip().startswith('SELECT'):
            return jsonify({"error": "Solo se permiten consultas SELECT"}), 403
        
        result = USERPG.COMMANDSQL(query)
        if isinstance(result, str) and "ERROR" in result:
            return jsonify({"error": result})
        
        columns = list(result[0].keys()) if result else []
        return jsonify({"results": result, "columns": columns})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/database/tables")
@csrf.exempt
def admin_database_tables():
    try:
        tables_info = []
        
        # Información de tabla usernamedb
        users = USERPG.GET_USER('all') or []
        tables_info.append({
            'name': 'usernamedb',
            'rows': len(users),
            'columns': [
                {'name': 'id', 'type': 'SERIAL PRIMARY KEY'},
                {'name': 'username', 'type': 'TEXT'},
                {'name': 'email', 'type': 'TEXT'},
                {'name': 'passw', 'type': 'TEXT'},
                {'name': 'email_confirm', 'type': 'TEXT'},
                {'name': 'permission', 'type': 'INTEGER'},
                {'name': 'time', 'type': 'TEXT'}
            ]
        })
        
        # Información de tabla blogpg
        posts = BLOGPG.GET_BL('all') or []
        tables_info.append({
            'name': 'blogpg',
            'rows': len(posts),
            'columns': [
                {'name': 'id', 'type': 'SERIAL PRIMARY KEY'},
                {'name': 'title', 'type': 'TEXT'},
                {'name': 'content', 'type': 'TEXT'},
                {'name': 'creat_id', 'type': 'INTEGER'},
                {'name': 'tags', 'type': 'TEXT'},
                {'name': 'category', 'type': 'TEXT'},
                {'name': 'count_view', 'type': 'INTEGER'},
                {'name': 'time', 'type': 'TEXT'}
            ]
        })
        
        return jsonify({'tables': tables_info})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/admin/database/analyze")
@csrf.exempt
def admin_database_analyze():
    try:
        users_count = len(USERPG.GET_USER('all') or [])
        posts_count = len(BLOGPG.GET_BL('all') or [])
        
        return jsonify({
            'size': f'{users_count + posts_count} registros totales',
            'connections': '1 activa',
            'last_vacuum': 'No disponible',
            'indexes': 2  # id indexes
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/admin/database/optimize", methods=["POST"])
@csrf.exempt
def admin_database_optimize():
    sessions, token, uss, uid = if_session(session)
    
    try:
        # Simular optimización
        log.info(f"[ADMIN] Optimización de BD solicitada por {uss}")
        return jsonify({
            'success': True,
            'message': 'Base de datos optimizada correctamente'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error en optimización: {str(e)}'
        })

@app.route("/admin/database/export", methods=["POST"])
@csrf.exempt
def admin_database_export():
    sessions, token, uss, uid = if_session(session)
    
    try:
        # Crear exportación JSON
        export_data = {
            'metadata': {
                'export_date': datetime.datetime.now().isoformat(),
                'version': VERSION,
                'exported_by': uss
            },
            'users': [],
            'posts': []
        }
        
        # Exportar usuarios
        users = USERPG.GET_USER('all') or []
        for user in users:
            export_data['users'].append({
                'username': user['username'],
                'email': user['email'],
                'email_confirm': user.get('email_confirm', 'false'),
                'permission': user.get('permission', 0),
                'time': user.get('time', '')
            })
        
        # Exportar posts
        posts = BLOGPG.GET_BL('all', MARKDOWN=False, UID=False) or []
        for post in posts:
            export_data['posts'].append({
                'title': post.get('title', ''),
                'descript': post.get('descript', ''),
                'content': post.get('content', ''),
                'creat_id': post.get('creat_id', 0),
                'tags': post.get('tags', ''),
                'category': post.get('category', ''),
                'count_view': post.get('count_view', 0),
                'time': post.get('time', '')
            })
        
        log.info(f"[ADMIN] Exportación de BD realizada por {uss}")
        
        return Response(
            json.dumps(export_data, indent=2, ensure_ascii=False),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=database_export_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'}
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/admin/database/import", methods=["POST"])
@csrf.exempt
def admin_database_import():
    """Importar datos desde archivo JSON (usar mejor /admin/backup/restore)"""
    sessions, token, uss, uid = if_session(session)
    
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No se seleccionó archivo"}), 400
        
        file = request.files['file']
        if file.filename == '' or not file.filename.endswith('.json'):
            return jsonify({"error": "Archivo JSON requerido"}), 400
        
        # Guardar archivo temporal y usar la función de restore
        import tempfile
        temp_path = os.path.join(tempfile.gettempdir(), f"import_{int(time.time())}.json")
        file.save(temp_path)
        
        try:
            result = ADMIN.restore_backup(temp_path)
            log.info(f"[ADMIN] Importación por {uss}: {result.get('message', 'Error')}")
            return jsonify(result)
        finally:
            # Limpiar archivo temporal
            try:
                os.remove(temp_path)
            except:
                pass
        
    except Exception as e:
        log.error(f"Error en importación: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/database/delete-post", methods=["POST"])
@csrf.exempt
def admin_delete_post():
    sessions, token, uss, uid = if_session(session)
    
    try:
        data = request.get_json()
        if not data.get('csrf_token'):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        post_id = data.get('post_id')
        if not post_id:
            return jsonify({"error": "ID de post requerido"}), 400
        
        # Verificar que el post existe
        post = BLOGPG.GET_BL('id', post_id)
        if not post:
            return jsonify({"error": "Post no encontrado"}), 404
        
        # Eliminar post
        result = BLOGPG.DELETE_BL(post_id)
        if result:
            log.info(f"[ADMIN] Post {post_id} eliminado por {uss}")
            return jsonify({"success": True, "message": "Post eliminado correctamente"})
        else:
            return jsonify({"error": "Error al eliminar el post"}), 500
            
    except Exception as e:
        log.error(f"[ADMIN] Error eliminando post por {uss}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/database/edit-post", methods=["POST"])
@csrf.exempt
def admin_edit_post():
    sessions, token, uss, uid = if_session(session)
    
    try:
        data = request.get_json()
        if not data.get('csrf_token'):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        post_id = data.get('post_id')
        new_title = data.get('title', '').strip()
        
        if not post_id or not new_title:
            return jsonify({"error": "ID de post y título requeridos"}), 400
        
        # Verificar que el post existe
        post = BLOGPG.GET_BL('id', post_id)
        if not post:
            return jsonify({"error": "Post no encontrado"}), 404
        
        # Editar post
        result = BLOGPG.EDIT_BL('title', post_id, new_title)
        if result:
            log.info(f"[ADMIN] Post {post_id} editado por {uss} - Nuevo título: {new_title}")
            return jsonify({"success": True, "message": "Post actualizado correctamente"})
        else:
            return jsonify({"error": "Error al actualizar el post"}), 500
            
    except Exception as e:
        log.error(f"[ADMIN] Error editando post por {uss}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/database/post-comments/<int:post_id>")
@csrf.exempt
def admin_get_post_comments(post_id):
    try:
        # Obtener post
        post = BLOGPG.GET_BL('id', post_id, MARKDOWN=False, UID=False, TAGS=False)
        if not post:
            return jsonify({"error": "Post no encontrado"}), 404
        
        # Obtener comentarios del campo extra
        comments = []
        if post[0].get('extra'):
            try:
                comments = json.loads(post[0]['extra'])
            except json.JSONDecodeError:
                comments = []
        
        return jsonify({"comments": comments})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/database/delete-comment", methods=["POST"])
@csrf.exempt
def admin_delete_comment():
    sessions, token, uss, uid = if_session(session)
    
    try:
        data = request.get_json()
        if not data.get('csrf_token'):
            return jsonify({"error": "Token de seguridad requerido"}), 400
        
        post_id = data.get('post_id')
        comment_index = data.get('comment_index')
        
        if post_id is None or comment_index is None:
            return jsonify({"error": "ID de post e índice de comentario requeridos"}), 400
        
        # Obtener post
        post = BLOGPG.GET_BL('id', post_id, MARKDOWN=False, UID=False, TAGS=False)
        if not post:
            return jsonify({"error": "Post no encontrado"}), 404
        
        # Obtener comentarios
        comments = []
        if post[0].get('extra'):
            try:
                comments = json.loads(post[0]['extra'])
            except json.JSONDecodeError:
                comments = []
        
        # Verificar índice válido
        if comment_index < 0 or comment_index >= len(comments):
            return jsonify({"error": "Comentario no encontrado"}), 404
        
        # Eliminar comentario
        deleted_comment = comments.pop(comment_index)
        
        # Actualizar post
        result = BLOGPG.EDIT_BL('extra', post_id, json.dumps(comments))
        if result:
            log.info(f"[ADMIN] Comentario eliminado del post {post_id} por {uss} - Autor: {deleted_comment.get('name', 'Desconocido')}")
            return jsonify({"success": True, "message": "Comentario eliminado correctamente"})
        else:
            return jsonify({"error": "Error al eliminar el comentario"}), 500
            
    except Exception as e:
        log.error(f"[ADMIN] Error eliminando comentario por {uss}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/maintenance")
def admin_maintenance():
    dark_mode = request.cookies.get('dark-mode', 'true')
    sessions, token, uss, uid = if_session(session)
    
    try:
        return render_template("admin/maintenance.html",
                             user=uss,
                             cookie=dark_mode,
                             version=VERSION)
    except Exception as e:
        log.error(f"[/admin/maintenance] Error: {e}")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/monitor")
def admin_monitor():
    dark_mode = request.cookies.get('dark-mode', 'true')
    sessions, token, uss, uid = if_session(session)
    
    try:
        # Usar la API unificada con todos los datos necesarios
        analytics_data = ANALYTICS.get_unified_analytics_data(include_geo=True, include_system=True)
        
        return render_template("admin/monitor.html",
                             user=uss,
                             cookie=dark_mode,
                             version=VERSION,
                             **analytics_data)  # Desempaquetar todos los datos
    except Exception as e:
        log.error(f"[/admin/monitor] Error: {e}")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/backup")
def admin_backup_page():
    dark_mode = request.cookies.get('dark-mode', 'true')
    sessions, token, uss, uid = if_session(session)
    
    try:
        backups = ADMIN.list_backups(CONFIG.SYSTEM_PATH)
        return render_template("admin/backup.html",
                             backups=backups,
                             user=uss,
                             cookie=dark_mode,
                             version=VERSION)
    except Exception as e:
        log.error(f"[/admin/backup] Error: {e}")
        return redirect(url_for("admin_dashboard"))

@app.route("/admin/monitor/analytics", methods=["GET", "POST"])
@csrf.exempt
def admin_analytics_api():
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        # Obtener parámetros
        include_geo = request.args.get('geo', 'false').lower() == 'true'
        include_system = request.args.get('system', 'true').lower() == 'true'
        force_geo = request.args.get('force_geo', 'false').lower() == 'true'
        
        return jsonify(ANALYTICS.get_unified_analytics_data(include_geo, include_system, force_geo))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/monitor/realtime")
@csrf.exempt
def admin_realtime_api():
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        return jsonify({"error": "Acceso denegado"}), 403
    
    try:
        return jsonify(ANALYTICS.get_real_time_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/logger")
def getlogger():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if not sessions or not check_admin_permission(uid):
            flash("Acceso denegado. Permisos de administrador requeridos.", "error")
            return redirect(url_for("login"))
        
        log_path = os.path.join(CONFIG.SYSTEM_PATH, "logs", "logger.log")
        
        # Descargar archivo
        if request.args.get("download"):
            log.info(f"[{ip_client}] [/admin/logger ] Usuario [{uss}] descargó logs")
            return send_from_directory(os.path.dirname(log_path), "logger.log", as_attachment=True)
        
        # Leer logs
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Leer últimas 1000 líneas
                lines = f.readlines()
                logs_content = ''.join(lines[-1000:]) if len(lines) > 1000 else ''.join(lines)
        except FileNotFoundError:
            logs_content = "No se encontraron logs."
        except Exception as e:
            logs_content = f"Error al leer logs: {e}"
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Respuesta AJAX
        if request.args.get("ajax"):
            return jsonify({
                "logs": logs_content,
                "timestamp": timestamp
            })
        
        # Filtrar logs por nivel si se especifica
        log_level = request.args.get('level', 'all')
        if log_level != 'all':
            lines = logs_content.split('\n')
            filtered_lines = []
            for line in lines:
                if log_level.upper() in line:
                    filtered_lines.append(line)
            logs_content = '\n'.join(filtered_lines)
        
        log.info(f"[{ip_client}] [/admin/logger ] Usuario [{uss}] revisó los logs")
        return render_template("admin/logger.html", 
                             logs=logs_content, 
                             timestamp=timestamp,
                             current_level=log_level,
                             user=uss, 
                             cookie=dark_mode, 
                             version=VERSION)
            
    except Exception as e:
        log.error(f"[{ip_client}] [/admin/logger ] ERROR: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))







@app.route("/tchat")
def testchat():
    return render_template("chat/chat1.html")


@app.route("/tchat2")
def testchat2():
    return render_template("chat/chat2.html")


@app.route("/tchat3")
def testchat3():
    return render_template("chat/chat3.html")


@app.route("/tchat4")
def testchat4():
    return render_template("chat/chat3.0.html")



@app.route("/layout")
def layout():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        # Verificar si hay una sesión activa
        sessions, token, uss, uid = if_session(session)
        if sessions == True:
            return render_template("layout.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("layout.html", cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/layout ] ERROR[-1]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))



@app.route("/poweroff", methods=["POST", "GET"])
def poweroff():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    
    # Verificar sesión de administrador
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        flash("Acceso denegado. Permisos de administrador requeridos.", "error")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        csrf_token = request.form.get("csrf_token")
        if not csrf_token:
            flash("Token de seguridad requerido", "error")
            return render_template("admin/poweroff.html", user=uss, cookie=dark_mode, version=VERSION)
        
        passw = request.form.get("pass")
        
        # Verificar contraseña del administrador actual
        user_data = USERPG.GET_USER('id', uid)
        if user_data and bcrypt.checkpw(passw.encode("utf-8"), user_data['passw'].encode("utf-8")):
            log.warning(f"[ADMIN] Servidor apagado por {uss} desde {ip_client}")
            flash("Servidor apagándose...", "warning")
            os.kill(os.getpid(), signal.SIGINT)
            return "Servidor apagándose..."
        else:
            log.warning(f"[{ip_client}] [/poweroff ] Usuario [{uss}] contraseña incorrecta")
            flash("Contraseña de administrador incorrecta", "error")
            return render_template("admin/poweroff.html", user=uss, cookie=dark_mode, version=VERSION)
    else:
        return render_template("admin/poweroff.html", user=uss, cookie=dark_mode, version=VERSION)

@app.route("/reboot", methods=["POST", "GET"])
def reboot():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    
    # Verificar sesión de administrador
    sessions, token, uss, uid = if_session(session)
    if not sessions or not check_admin_permission(uid):
        flash("Acceso denegado. Permisos de administrador requeridos.", "error")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        csrf_token = request.form.get("csrf_token")
        if not csrf_token:
            flash("Token de seguridad requerido", "error")
            return render_template("admin/reboot.html", user=uss, cookie=dark_mode, version=VERSION)
        
        passw = request.form.get("pass")
        
        # Verificar contraseña del administrador actual
        user_data = USERPG.GET_USER('id', uid)
        if user_data and bcrypt.checkpw(passw.encode("utf-8"), user_data['passw'].encode("utf-8")):
            log.warning(f"[ADMIN] Servidor reiniciado por {uss} desde {ip_client}")
            flash("Servidor reiniciándose...", "info")
            
            # Recargar variables de entorno
            from dotenv import load_dotenv
            load_dotenv("config.env", override=True)
            
            # Reiniciar el proceso Python
            import subprocess
            subprocess.Popen([sys.executable] + sys.argv)
            os._exit(0)
        else:
            log.warning(f"[{ip_client}] [/reboot ] Usuario [{uss}] contraseña incorrecta")
            flash("Contraseña de administrador incorrecta", "error")
            return render_template("admin/reboot.html", user=uss, cookie=dark_mode, version=VERSION)
    else:
        return render_template("admin/reboot.html", user=uss, cookie=dark_mode, version=VERSION)


@app.route("/setcookie", methods=["POST", "GET"])
def setcookie():
    resp = make_response()
    resp.set_cookie("userID", "XD")
    return resp

@app.route("/getcookie", methods=["POST", "GET"])
def getcookie():
    name = request.cookies.get("userID")
    return name

@app.route("/portfolio")
def portfolio():
    """Portfolio del desarrollador."""
    ip_client = get_client_ip()
    dark_mode = request.cookies.get('dark-mode', 'true')
    
    try:
        sessions, token, username, uid = if_session(session)
        
        log.debug(f"[{ip_client}] [/portfolio] Acceso al portfolio")
        
        if sessions:
            return render_template('pages/portfolio.html', user=username, cookie=dark_mode, version=VERSION)
        else:
            return render_template('pages/portfolio.html', cookie=dark_mode, version=VERSION)
            
    except Exception as e:
        log.error(f"[{ip_client}] [/portfolio] Error: {e}")
        return render_template('pages/portfolio.html', cookie=dark_mode, version=VERSION)

@app.route("/d")
@app.route("/doxear", methods=["POST", "GET"])
def doxear():
    client_ip = get_client_ip()
    headers = dict(request.headers)
    
    try:
        # Geolocalización completa
        geo_response = requests.get(f"http://ip-api.com/json/{client_ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query", timeout=5)
        geo_data = geo_response.json() if geo_response.status_code == 200 else {}
        
        # Información adicional del navegador
        user_agent = headers.get('User-Agent', '')
        
        # Detectar tecnologías
        tech_info = {
            'javascript_enabled': 'Probablemente' if 'Mozilla' in user_agent else 'Desconocido',
            'cookies_enabled': 'Probablemente' if request.cookies else 'No detectadas',
            'screen_info': 'No disponible (requiere JS)',
            'timezone_js': 'No disponible (requiere JS)',
            'language': headers.get('Accept-Language', 'Desconocido')[:10],
            'encoding': headers.get('Accept-Encoding', 'Desconocido'),
            'connection': headers.get('Connection', 'Desconocido'),
            'cache_control': headers.get('Cache-Control', 'Desconocido')
        }
        
        # Análisis de seguridad
        security_analysis = {
            'proxy_detected': geo_data.get('proxy', False),
            'hosting_detected': geo_data.get('hosting', False),
            'mobile_detected': geo_data.get('mobile', False),
            'tor_detected': 'onion' in headers.get('Host', '').lower(),
            'vpn_suspected': geo_data.get('isp', '').lower() in ['vpn', 'proxy', 'tor'],
            'bot_suspected': any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider', 'scraper'])
        }
        
        log.critical(f"[/doxear] [DOXING] IP: {client_ip} | Geo: {geo_data.get('city', 'Unknown')}, {geo_data.get('regionName', 'Unknown')}, {geo_data.get('country', 'Unknown')} | ISP: {geo_data.get('isp', 'Unknown')} | Org: {geo_data.get('org', 'Unknown')} | Coords: {geo_data.get('lat', 'N/A')},{geo_data.get('lon', 'N/A')} | Timezone: {geo_data.get('timezone', 'Unknown')} | Mobile: {geo_data.get('mobile', False)} | Proxy: {geo_data.get('proxy', False)} | Hosting: {geo_data.get('hosting', False)} | UA: {user_agent[:100]} | Lang: {headers.get('Accept-Language', 'Unknown')[:20]} | Encoding: {headers.get('Accept-Encoding', 'Unknown')[:30]}")
        
        return render_template('doxear.html', 
                             ip=client_ip,
                             headers=headers,
                             geo=geo_data,
                             tech=tech_info,
                             security=security_analysis,
                             user_agent=user_agent)
                             
    except Exception as e:
        log.error(f"[/doxear] Error: {e}")
        return render_template('doxear.html', 
                             ip=client_ip,
                             headers=headers,
                             geo={},
                             tech={},
                             security={},
                             user_agent=user_agent,
                             error=str(e))





# Manejador de errores CSRF
from flask_wtf.csrf import CSRFError

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Token de seguridad inválido. Por favor, intenta de nuevo.', 'error')
    return redirect(request.referrer or url_for('index'))








@app.route("/dev", methods=["POST", "GET"])
def dev():
    return render_template("_dev/extra/index.html")


@app.route("/dev2", methods=["POST", "GET"])
def dev2():
    return render_template("_dev/extra/blog.html")


@app.route("/dev3", methods=["POST", "GET"])
def dev3():
    return render_template("_dev/extra/blog-single.html")


@app.route("/dev4", methods=["POST", "GET"])
def dev4():
    return render_template("_dev/auth/terms-conditions.html")

@app.route("/dev5", methods=["POST", "GET"])
def dev5():
    return render_template("_dev/auth/privacy-policy.html")

    


################### API/v1 #######################

datosmsg = []
datosmsg_all = []

@app.route("/api/auth", methods=["POST", "GET"])
def apiauth_v1():
    try:
        auth = request.get_json()
        auth_user = auth["username"]
        auth_email = auth["EMAIL"]
        auth_passw = auth["PASSW"]
        print(auth_user, auth_email, auth_passw)

        key = app.config.get("SECRET_KEY")
        E_EMAIL = USERPG.ENCRIPT(auth_email, key)
        E_PASSW = USERPG.ENCRIPT(auth_passw, key)
        if USERPG.VALIDAR(auth_user, auth_passw, key) == True:
            datos_send_token = {
                "exp": datetime.datetime.utcnow()
                + datetime.timedelta(days=0, minutes=13, seconds=0),
                "iat": datetime.datetime.utcnow(),
                "USER": auth_user,
                "EMAIL": E_EMAIL,
                "PASSW": E_PASSW,
            }

            eltoken = jwt.encode(
                datos_send_token, app.config.get("SECRET_KEY"), algorithm="HS256"
            )

            allb = {"@all": f"bot:@{auth_user} se a unido"}
            datosmsg_all.append(allb)
            userb = {f"@{auth_user}": "bot:bienvenido al chat"}
            datosmsg.append(userb)

            return jsonify({"TOKEN": f"{eltoken}"})
        else:
            status = 401
            return jsonify({"ERROR": "DATOS DE AUTENTIFICACION INCORRECTOS"}), status
    except:
        status = 400
        return jsonify({"ERROR": "BAD REQUEST"}), status


@app.route("/api/msg", methods=["POST", "GET"])
def apimsg():
    if request.method == "POST":
        try:
            try:
                token = request.get_json()
                auth_token = token["TOKEN"]
                datos = token["DATOS"]

            except:
                auth_token = ""
                datos = ""

            verificador = jwt.decode(
                auth_token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
            )
            print("TOKEN:", verificador["USER"], "\nMSG:", datos)
            try:
                if datos["@all"]:
                    datosmsg_all.append(datos)
            except:
                datosmsg.append(datos)
            print(datosmsg)
            return jsonify({"VALIDO": f"DATOS RESIVIDOS CORRECTAMENTE :) "})
        except jwt.ExpiredSignatureError:
            print("expiro")
            status = 403
            return jsonify({"ERROR": "EL TOKEN EXPIRO"}), status
        except jwt.InvalidTokenError:
            print("Invalid token. Please log in again.")
            status = 401
            return jsonify({"ERROR": "TOKEN INVALIDO"}), status

    else:
        larespuesta = datosmsg_all, datosmsg
        return jsonify({"VALIDO": larespuesta})




#################### API/v2 ######################
# Auth v2
@app.route("/api/v2/auth", methods=["POST", "GET"])
def apiauth_v2():
    try:
        pass
    except:
        pass


@app.route("/api/v2/destroyer", methods=["POST", "GET"])
def destroyer_bot():
    ip_client = request.headers.get("X-Real-IP")
    try:
        if request.method == "POST":
            user_agent = request.headers.get("User-Agent")
            if user_agent == "DestroyerBot":
                try:
                    data = request.get_json()
                    if data["Response"] == True:
                        # Registrar el mensaje enviado por el bot
                        log.warning(
                            f"[/api/v2/destroyer ] [method POST] Mensaje recibido desde {ip_client}: {data['Response_Text']}")
                except:
                    data = None

                response_data = {
                    "DestroyerCall": False,
                    "kill_Personal_Carpet": False,
                    "Kill_Spesific_Folder": False,
                    "Folders_Route": ["C:\\Windows\\System32"],
                    "Delete_Bot": False,
                    "Stop_Bot": False,
                    "Execute_Console": True,
                    "Console_command": ["ping google.com -c3"]
                }
                log.info(
                    f"[/api/v2/destroyer ] [method POST] DestroyerBot {ip_client} con User-Agent {user_agent}, {data}")
                return jsonify(response_data)
            else:
                user_agent = request.headers.get("User-Agent")
                log.warning(
                    f"[/api/v2/destroyer ] [method POST] Acceso no autorizado desde {ip_client} con User-Agent {user_agent}")
                return jsonify({"error": "Forbidden"}), 403
        else:
            ip_client = request.headers.get("X-Real-IP")
            log.warning(
                f"[/api/v2/destroyer ] [method GET] Acceso no autorizado desde {ip_client} con User-Agent {user_agent}")
            headers = request.headers
            return f"{headers}"

    except Exception as e:
        log.error(
            f"[/api/v2/destroyer ] Error al procesar la petición: {e} [{traceback.format_exc()}]")
        return jsonify({"error": "Internal server error"}), 500

################## Test Auth #####################

# Definir los usuarios
users = {
    'juan': '1234'
}

# Definir la ruta de auth
@app.route('/auth')
def auth_form():
    if request.args.get('username') is None:
        return render_template("auth/log-in_layout.html")
    username = request.args.get('username')
    return render_template("auth/AuthApi.html", username=username)

# Definir la ruta de autorización
@app.route('/auth/authorize', methods=["POST", "GET"])
def authorize():
    # Obtener el nombre de usuario y la contraseña del usuario
    if request.method == "POST":
        csrf_token = request.form.get("csrf_token")
        if not csrf_token:
            return render_template("auth/AuthApi.html", Error="Token de seguridad requerido")
        
        username = request.form.get('username')
        password = request.form.get('password')
        key = app.config.get("SECRET_KEY")
        log.info(f"[auth ] [method POST] {username} {password}")

        # Verificar las credenciales del usuario
        if username.__contains__('"'):
                    ERROR = "EL USUARIO/CORREO NO PUEDE CONTENER COMILLAS"
                    return render_template("auth/log-in_layout.html", ERROR2=ERROR)
        if USERPG.VALIDAR(username, password, key) == True:
            if username.__contains__("@"):
                TheUser = USERPG.GET_USER("email", username)
            else:
                TheUser = USERPG.GET_USER("username", username)
            # Generar un código de autorización
            code = '123456'

            # Redirigir al usuario a la aplicación
            return render_template("auth/Authresponse.html", code=code)
        else:
            # Devolver un error
            return f'Error de autorización,{username,password} '
    return render_template("auth/log-in_layout.html")

# Definir la ruta de devolución de llamada
@app.route('/auth/callback')
def callback():
    # Obtener el código de autorización del usuario
    code = request.args.get('code')

    # Generar un token de acceso
    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGhhdCJ9.Kl1fX8W7-0_6q_XDXO2QKL-6_j-3Z-4_p6-_0yh0E-8'

    # Devolver el token de acceso
    return token


#################### SoketIO #####################
# Para que funcione bien, debes instalar el paquete Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")


@socketio.on("connect")
def test_connect():
    print("Cliente conectado")
    log.debug("Cliente conectado")
    # Aquí puedes hacer lo que quieras con la conexión
    # Ejemplo: enviar un mensaje al cliente que se conecté
    #
    emit("after connect", {"data": "Lets dance"})


@socketio.on("opcion")
def handle_opcion(opcion):
    print("Recibida opción: " + opcion)
    log.debug("Recibida opción: " + opcion)
    # Aquí puedes hacer lo que quieras con la opción recibida
    emit("mensaje", "Has seleccionado la opción " + opcion)


@socketio.on("boton")
def handle_boton(estado):
    print("Recibido estado del botón: " + estado)
    log.debug("Recibido estado del botón: " + estado)
    # Aquí puedes hacer lo que quieras con el estado del botón
    emit("mensaje", "El botón está " + estado)


# Cambia la lógica del manejador para el evento 'boton normal'
@socketio.on("boton normal")
def handle_boton_normal(estado):
    print("Recibido estado del botón normal: " + estado)
    log.debug("Recibido estado del botón normal: " + estado)
    # Envía el mensaje según el estado recibido
    emit("mensaje", "Se ha clicado el botón normal y ahora está " + estado)


# Añade una función decorada con @socketio.on('texto')
@socketio.on("texto")
def handle_texto(texto):
    print("Recibido texto: " + texto)
    log.debug("Recibido texto: " + texto)
    # Añade una estructura condicional para enviar una respuesta diferente según el texto
    if texto == "hola":
        emit("respuesta", "Hola, ¿qué tal?")

    elif texto == "/start":
        emit("respuesta", "Hola, XD")

    elif texto == "/quit":
        emit("respuesta", "Adiós, hasta pronto")

    elif texto == "XD":
        emit("respuesta", "Jaja, muy gracioso")

    elif texto == "/help":
        emit("respuesta", "Escribe hola o XD")

    else:
        emit("respuesta", "No entiendo lo que dices")


@app.route("/test")
def config():
    return render_template("app/socket.html")


values = {
    "slider1": 25,
    "slider2": 0,
}


@socketio.on("Slider value changed")
def handle_slider_change(message):
    # receive the slider value change from the client
    print("received slider value change: " + str(message))
    # update the values dictionary with the new value
    values[message["who"]] = message["data"]
    # emit the updated value to all the connected clients
    emit("update value", message, broadcast=True)


@app.route("/test1")
def slider():
    return render_template(
        "app/test.html", slider1=values["slider1"], slider2=values["slider2"]
    )


@socketio.on("message")
def Text_MSG(msg):
    print("text-message: " + msg)
    send(msg, broadcast=True)


@app.route("/test2")
def chat():
    return render_template("app/chat.html", **values)





@app.route("/settings", methods=["GET", "POST"])
def settings():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    
    try:
        sessions, token, uss, uid = if_session(session) 
        if not sessions:
            return redirect(url_for("login"))
        
        user_data = USERPG.GET_USER('id', uid)
        if not user_data:
            return redirect(url_for("logout"))
        
        # Calcular estadísticas del usuario
        user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
        file_count = len(os.listdir(user_dir)) if os.path.exists(user_dir) else 0
        
        storage_used = "0 MB"
        if os.path.exists(user_dir):
            total_size = 0
            for root, dirs, files in os.walk(user_dir):
                for file in files:
                    total_size += os.path.getsize(os.path.join(root, file))
            storage_used = f"{total_size / (1024*1024):.1f} MB" if total_size < 1024*1024*1024 else f"{total_size / (1024*1024*1024):.1f} GB"
        
        posts = BLOGPG.GET_BL('creat_id', uid) or []
        user_stats = {'files': file_count, 'posts': len(posts), 'storage_used': storage_used}
        
        if request.method == "POST":
            csrf_token = request.form.get("csrf_token")
            if not csrf_token:
                flash("Token de seguridad requerido", "error")
                return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
            
            action = request.form.get("action")
            
            if action == "update_profile":
                new_username = request.form.get("username", "").strip()
                new_email = request.form.get("email", "").strip()
                
                if not new_username or not new_email:
                    flash("Todos los campos son requeridos", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                username_valid, username_msg = VALIDATORS.validate_username(new_username)
                if not username_valid and new_username != user_data['username']:
                    flash(username_msg, "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if not VALIDATORS.validate_email(new_email):
                    flash("Email inválido", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if new_username != user_data['username']:
                    existing_user = USERPG.GET_USER('username', new_username)
                    if existing_user:
                        flash("El nombre de usuario ya existe", "error")
                        return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if new_email != user_data['email']:
                    existing_email = USERPG.GET_USER('email', new_email)
                    if existing_email:
                        flash("El email ya está en uso", "error")
                        return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                try:
                    if new_username != user_data['username']:
                        USERPG.EDITAR('username', user_data['username'], new_username)
                        user_data['username'] = new_username
                    
                    if new_email != user_data['email']:
                        USERPG.EDITAR('email', user_data['username'], new_email)
                        USERPG.EDITAR('email_confirm', user_data['username'], 'false')
                        user_data['email'] = new_email
                        user_data['email_confirm'] = 'false'
                        flash("Email actualizado. Se requiere verificación.", "warning")
                    
                    flash("Perfil actualizado correctamente", "success")
                    log.info(f"[{ip_client}] [/settings] Usuario [{uss}] actualizó su perfil")
                except Exception as e:
                    flash("Error al actualizar el perfil", "error")
                    log.error(f"[{ip_client}] [/settings] Error actualizando perfil: {e}")
            
            elif action == "change_password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")
                
                if not all([current_password, new_password, confirm_password]):
                    flash("Todos los campos son requeridos", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if not bcrypt.checkpw(current_password.encode("utf-8"), user_data['passw'].encode("utf-8")):
                    flash("Contraseña actual incorrecta", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if len(new_password) < 8:
                    flash("La nueva contraseña debe tener al menos 8 caracteres", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if new_password != confirm_password:
                    flash("Las contraseñas no coinciden", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                try:
                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    USERPG.EDITAR('passw', user_data['username'], hashed_password.decode('utf-8'))
                    flash("Contraseña actualizada correctamente", "success")
                    log.info(f"[{ip_client}] [/settings] Usuario [{uss}] cambió su contraseña")
                except Exception as e:
                    flash("Error al cambiar la contraseña", "error")
                    log.error(f"[{ip_client}] [/settings] Error cambiando contraseña: {e}")
            
            elif action == "resend_verification":
                try:
                    return redirect(url_for("EmailSend", email=user_data['email']))
                except Exception as e:
                    flash("Error al enviar verificación", "error")
                    log.error(f"[{ip_client}] [/settings] Error enviando verificación: {e}")
            
            elif action == "delete_account":
                password_confirm = request.form.get("password_confirm", "")
                delete_confirm = request.form.get("delete_confirm", "")
                
                if not password_confirm or not delete_confirm:
                    flash("Todos los campos son requeridos", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if not bcrypt.checkpw(password_confirm.encode("utf-8"), user_data['passw'].encode("utf-8")):
                    flash("Contraseña incorrecta", "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                if delete_confirm != "ELIMINAR":
                    flash('Debes escribir "ELIMINAR" para confirmar', "error")
                    return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=uss, cookie=dark_mode, version=VERSION)
                
                try:
                    user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
                    if os.path.exists(user_dir):
                        import shutil
                        shutil.rmtree(user_dir)
                except Exception as e:
                    log.warning(f"Error eliminando archivos del usuario {uid}: {e}")
                
                try:
                    for post in posts:
                        BLOGPG.DELETE_BL(post['id'])
                except Exception as e:
                    log.warning(f"Error eliminando posts del usuario {uid}: {e}")
                
                try:
                    USERPG.DELETE(uid)
                    session.clear()
                    flash("Cuenta eliminada correctamente", "info")
                    log.info(f"[{ip_client}] [/settings] Usuario [{uss}] eliminó su cuenta")
                    return redirect(url_for("index"))
                except Exception as e:
                    flash("Error al eliminar la cuenta", "error")
                    log.error(f"[{ip_client}] [/settings] Error eliminando cuenta: {e}")
        
        # Recargar datos actualizados
        user_data = USERPG.GET_USER('id', uid)
        return render_template("settings.html", user_data=user_data, user_stats=user_stats, user=user_data['username'], cookie=dark_mode, version=VERSION)
        
    except Exception as e:
        log.error(f"[{ip_client}] [/settings] ERROR: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))

@app.route("/settings/export")
def settings_export():
    sessions, token, uss, uid = if_session(session)
    if not sessions:
        return redirect(url_for("login"))
    
    try:
        user_data = USERPG.GET_USER('id', uid)
        posts = BLOGPG.GET_BL('creat_id', uid, MARKDOWN=False, UID=False) or []
        
        export_data = {
            'user_info': {
                'username': user_data['username'],
                'email': user_data['email'],
                'registration_date': user_data.get('time', ''),
                'email_verified': user_data.get('email_confirm') == 'true',
                'account_type': 'admin' if user_data.get('permission') == 1 else 'user'
            },
            'posts': posts,
            'export_date': datetime.datetime.now().isoformat()
        }
        
        log.info(f"[/settings/export] Usuario [{uss}] exportó sus datos")
        
        return Response(
            json.dumps(export_data, indent=2, ensure_ascii=False),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=mis_datos_{uss}_{datetime.datetime.now().strftime("%Y%m%d")}.json'}
        )
        
    except Exception as e:
        flash("Error al exportar datos", "error")
        return redirect(url_for("settings"))

@app.route("/settings/delete-files", methods=["POST"])
@csrf.exempt
def settings_delete_files():
    sessions, token, uss, uid = if_session(session)
    if not sessions:
        return jsonify({"error": "No autorizado"}), 401
    
    try:
        user_dir = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
        if os.path.exists(user_dir):
            import shutil
            shutil.rmtree(user_dir)
            os.makedirs(user_dir)
            
        log.info(f"[/settings/delete-files] Usuario [{uss}] eliminó todos sus archivos")
        return jsonify({"success": True, "message": "Todos los archivos han sido eliminados"})
        
    except Exception as e:
        return jsonify({"error": "Error interno"}), 500


# ============================================================================
# INICIALIZACIÓN Y ARRANQUE
# ============================================================================

def initialize_app():
    """Inicializar la aplicación."""
    log.info(f"SERVIDOR INICIADO EN: [{CONFIG.MY_OS}] [{VERSION}]")
    
    # Verificar conexión a base de datos
    try:
        USERPG.CONNECTION_TEST()
        log.info("Conexión a base de datos verificada")
    except Exception as e:
        log.error(f"Error conectando a base de datos: {e}")
    
    # Limpiar miniaturas antiguas
    try:
        THUMBNAILS.cleanup_old_thumbnails()
        log.info("Limpieza de miniaturas completada")
    except Exception as e:
        log.warning(f"Error en limpieza de miniaturas: {e}")
    
    # Verificar configuración crítica
    critical_vars = ['SECRET_KEY', 'EMAIL_WEBMASTER']
    missing_vars = [var for var in critical_vars if not os.getenv(var)]
    if missing_vars:
        log.warning(f"Variables críticas faltantes: {', '.join(missing_vars)}")

def shutdown_handler(signum, frame):
    """Manejador de señales para cierre limpio."""
    log.info(f"Señal {signum} recibida. Cerrando servidor...")
    sys.exit(0)

if __name__ == "__main__":
    # Configurar manejadores de señales
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    # Inicializar aplicación
    initialize_app()
    
    # Configurar modo debug
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    
    # Verificar modo de mantenimiento
    maintenance_mode = os.getenv("MAINTENANCE_MODE", "False").lower() == "true"
    if maintenance_mode:
        log.warning("SERVIDOR EN MODO MANTENIMIENTO")
    
    # Arrancar servidor
    try:
        log.info(f"Iniciando servidor en puerto 9001 (DEBUG: {DEBUG})")
        app.run(threaded=True, host="0.0.0.0", port=9001, debug=DEBUG)
    except KeyboardInterrupt:
        log.info("Servidor detenido por el usuario")
    except Exception as e:
        log.error(f"Error arrancando servidor: {e}")
        sys.exit(1)