from psycopg.rows import dict_row
from dotenv import load_dotenv
import psycopg
import traceback
import jwt
import datetime
import cryptocode
import bcrypt
import random
import os
import argparse


######### LOGGER ###########
import logging
try:
    import LOGGER
except:
    pass

log = logging.getLogger("DATABASE")

############################


########## EDIT ############
load_dotenv("config.env") # carga las variables de entorno desde el archivo .env

HOST = os.getenv("HOST_DB")
PORT = os.getenv("PORT_DB")
DB_NAME = os.getenv("NAME_DB")
USERPG = os.getenv("USERPG_DB")
PASSWPG = os.getenv("PASSWPG_DB")

DB_PATH = f"postgresql://{USERPG}:{PASSWPG}@{HOST}:{PORT}/{DB_NAME}"
#DB_PATH = f"host={HOST} port={PORT} dbname={DB_NAME} username={USERPG} password={PASSWPG}"
############################


######### connection and cursor #########
try:
    con = psycopg.connect(DB_PATH, row_factory=dict_row)
    cur = con.cursor()
except Exception as e:
    log.error(f'[CONNECTION_TEST] [ERROR 1] {e}')
    pass

def recon():
    try:
        global con
        global cur
        con = psycopg.connect(DB_PATH, row_factory=dict_row)
        cur = con.cursor()
    except Exception as e:
        log.error(f'[CONNECTION_TEST] [ERROR 1] {e}')
        pass
##########################################


def CONNECTION_TEST():
    global con
    global cur
    "CONNECTION_TEST: This function is used to test the connection to the database"
    try:
        con_test = psycopg.connect(DB_PATH)
        cur_test = con_test.cursor()
        cur_test.execute('SELECT * FROM usernamedb')
        con_test.close()
        log.info("CONNECTION_TEST: OK (psycopg3) ")
        return f'\nCONECTADO CORRECTAMENTE A PostgreSQL\n'
    except Exception as e:
        ERROR = f"ERROR AL CONECTARSE A PostgreSQL:\n{e}"
        try:
            CREATE_TABLE()
            log.info("CONNECTION_TEST: OK (psycopg3)")
            return f'\nCONECTADO A PostgreSQL + TABLA DE DATOS CREADAS'
        except Exception as e:
            ERROR = f"ERROR AL CONECTARSE A PostgreSQL:\n{e}"
            log.error(f'[CONNECTION_TEST] [ERROR 1] {ERROR}')
            return ERROR


def E_TOKEN(datos, secretkey):
    """
    E_TOKEN(datos, secretkey)
    This function is used to encrypt the data into a token.

    datos: data to encrypt
    secretkey: key to encrypt the data with.

    return: token with the data encrypted.

    Example:
    E_TOKEN('data', 'key')

    return: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGhhdCJ9.Kl1fX8W7-0_6q_XDXO2QKL-6_j-3Z-4_p6-_0yh0E-8'   
    """

    try:
        DATA = {'DATOS': datos}
        DATA_ENCRYPT = jwt.encode(DATA, secretkey, algorithm="HS256")
        log.debug(f'[E_TOKEN:] [OK] [{DATA}]')
        return DATA_ENCRYPT
    except Exception as e:
        log.error(f'[E_TOKEN:] [ERROR] [{e}]')
        return f'ERROR FOR ENCRIPT TOKEN:\n{e}'


def D_TOKEN(datos, secretkey):
    """
    D_TOKEN(datos, secretkey)
    This function is used to decrypt the data from a token.

    datos: data to decrypt
    secretkey: key to decrypt the data with.

    return: data decrypted.

    Example:
    D_TOKEN('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGhhdCJ9.Kl1fX8W7-0_6q_XDXO2QKL-6_j-3Z-4_p6-_0yh0E-8', 'key')

    return: 'data'
    """

    try:
        DATA_UNENCRYPT = jwt.decode(datos, secretkey, algorithms=["HS256"])
        log.debug(f'[D_TOKEN:] [OK] [{DATA_UNENCRYPT}]')
        return DATA_UNENCRYPT
    except Exception as e:
        ERROR = f'ERROR FOR DECRIPT TOKEN:\n{e}'
        log.error(f'[D_TOKEN:] [ERROR] [{ERROR}]')
        return ERROR


def ENCRIPT(datos, secretkey):
    """
    ENCRIPT(datos, secretkey)
    This function is used to encrypt the data.

    datos: data to encrypt
    secretkey: key to encrypt the data with.

    return: data encrypted.

    Example:
    ENCRIPT('data', 'key')

    return: 'Kl1fX8W7-0_6q_XDXO2QKL-6_j-3Z-4_p6-_0yh0E-8'
    """

    try:
        DATA_ENCRYPT = cryptocode.encrypt(datos, secretkey)
        log.debug(f'[ENCRIPT:] [OK] [{DATA_ENCRYPT}]')
        return DATA_ENCRYPT
    except Exception as e:
        log.error(f'[ENCRIPT:] [ERROR] [{e}]')
        return f'ERROR FOR ENCRIPT:\n{e}'


def DESENCRIPT(datos, secretkey):
    """
    DESENCRIPT(datos, secretkey)
    This function is used to decrypt the data.

    datos: data to decrypt
    secretkey: key to decrypt the data with.

    return: data decrypted.

    Example:
    DESENCRIPT('Kl1fX8W7-0_6q_XDXO2QKL-6_j-3Z-4_p6-_0yh0E-8', 'key')

    return: 'data'
    """

    try:
        DATA_UNENCRYPT = cryptocode.decrypt(datos, secretkey)
        log.debug(f'[DESENCRIPT:] [OK] [{DATA_UNENCRYPT}]')
        return DATA_UNENCRYPT
    except Exception as e:
        log.error(f'[DESENCRIPT:] [ERROR] [{e}]')
        return f'ERROR FOR DESENCRIPT:\n{e}'

def CREATE_TABLE():    
    EXECREATE = 'CREATE TABLE IF NOT EXISTS usernamedb (id SERIAL PRIMARY KEY, username text, email text, passw text, email_confirm text, random text, data_auth text, image text, count_view integer, permission integer, extra text, time text)'
    try:
        recon()    
        cur.execute(EXECREATE)
        con.commit()
        con.close()
        log.info(f"[CREATE_TABLE:] [OK]")
        return f'TABLA DE DATOS CREADA'
    except Exception as e:
        ERROR = f"ERROR AL CREAR LA TABLA:\n{e}"
        if ERROR.__contains__("Unknown database"):
            try:
                recon()
                cur.execute(f'CREATE DATABASE {DB_NAME}')
                cur.execute(EXECREATE)
                con.close()
                log.info(f"[CREATE_TABLE:] [OK]")
                CONNECTION_TEST()
                return f'TABLA DE DATOS CREADA'
            except Exception as e:
                ERROR = f"ERROR AL CREAR LA TABLA:\n{e}"
                log.error(f"[CREATE_TABLE:] [ERROR] {ERROR}")
                return ERROR
        else:
            log.error(f"[CREATE_TABLE:] [ERROR2] {ERROR}")
            return ERROR


def INSERT_USER(USER='', EMAIL='', PASSW='', PERMISSION=0):
    """
    INSER_DB(USER='', EMAIL='', PASSW='')
    USER: The username name.
    EMAIL: The username email.
    PASSW: The username password.

    return: message with the data inserted.

    Example:
    INSERT_DB('username', 'email', 'passw')

    return: 'USUARIO CREADO CORRECTAMENTE'
    """
    try:
        comp1 = GET_USER('username', USER)
        if comp1 == None:
            comp2 = GET_USER('email', EMAIL)
            if comp2 == None:
                TIME = datetime.datetime.now()
                recon()
                cur.execute('INSERT INTO usernamedb (username, email, passw, permission, time)  VALUES (%s,%s,%s,%s,%s)', (USER, EMAIL, PASSW, PERMISSION, str(TIME)))
                con.commit()
                con.close
                log.info(
                    f"[INSERT_DB:] [OK] (username: {USER}, email: {EMAIL}, passw: {PASSW})")
                return f'Usuaro {USER} creado correctamente'
            else:
                log.debug(
                    f"[INSERT_DB:] [ERROR] EMAIL EXIST (username: {USER}, email: {EMAIL}, passw: {PASSW})")
                return f'El correo {EMAIL} ya existe'
        else:
            log.debug(
                f"[INSERT_DB:] [ERROR] USER EXIST (username: {USER}, email: {EMAIL}, passw: {PASSW})")
            return f'El usuario {USER} ya existe'
    except Exception as e:
        ERROR = f"ERROR AL INCERTAR EN LA TABLA:\n{e}"
        log.error(
            f"[INSERT_DB:] [ERROR] [{ERROR}] (username: {USER}, email: {EMAIL}, passw: {PASSW})")
        return ERROR



def GET_USER(TYPE='all', DATA_SEARCH=''):
    """
    SEARCH_DB(TYPE='username', DATA_SEARCH='')
    TYPE: The type of data to search.
    DATA_SEARCH: The data to search. (ID, USER, EMAIL, PASSW, EMAIL_CONFIRM, RANDOM, DATOS, EXTRA, TIME)

    return: list with the data searched.

    Example:
    SEARCH_DB('username', 'username')

    return: [1, 'username', 'email', 'passw', 'email_confirm', 'random', 'data_auth', 'image', 'count_view', 'permission', 'extra', 'time']
    """
    try:
        recon()
        TIPOS = ['id', 'username', 'email', 'passw', 'email_confirm', 'random', 'data_auth', 'image', 'count_view', 'permission', 'extra']
        if TYPE in TIPOS:
            cur.execute(f'SELECT * FROM usernamedb WHERE {TYPE}= %s', (DATA_SEARCH,))
            resp = []
            for row in cur.fetchall():
                row = dict(row)
                resp = row
            con.close()
            log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            if len(resp) == 0:
                return None
            return resp
            
        elif TYPE == 'TIME':
            resp = []
            cur.execute('SELECT * FROM usernamedb')
            for row in cur.fetchall():
                row = dict(row)
                if row["time"].__contains__(DATA_SEARCH):
                    resp.append(row)
            con.close
            log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            if len(resp) == 0:
                return None
            return resp
        elif TYPE == 'all':
            resp = []
            cur.execute('SELECT * FROM usernamedb')
            for row in cur.fetchall():
                row = dict(row)
                resp.append(row)
            con.close
            log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            if len(resp) == 0:
                return None
            return resp
        else:
            log.debug(f"[SEARCH_DB:] [None] (type: {TYPE}, data: {DATA_SEARCH})")
            return None
    except Exception as e:
        ERROR = f"ERROR AL BUSCAR EN LA TABLA:\n{e}"
        log.error(f"[SEARCH_DB:] [ERROR] [{ERROR}] (type: {TYPE}, data: {DATA_SEARCH}) [{traceback.format_exc()}]")
        return ERROR



def DELETE(UID):
    """
    DELETE(UID)
    US_EM: The username email or username name.

    return: True or False.

    Example:
    DELETE('uid')

    return: True
    """
    try:
        if GET_USER('id', UID) != None:
            recon()
            cur.execute('DELETE FROM usernamedb WHERE id= %s',(UID,))
            con.commit()
            con.close()
            log.info(f'[DELETEBL:] [OK] (ID: {UID})')
            return True
        else:
            log.debug(f'[DELETEBL:] [None] (ID: {UID})')
            return False
    except Exception as e:
        ERROR = f'ERROR AL BORRAR:\n{e}'
        log.error(f'[DELETEBL:] [ERROR] (ERROR={ERROR})')
        return ERROR

def EDITAR(TYPE='username', USER='', NEWD=''):
    """
    TYPE: "ID", "USER", "EMAIL", "PASSW", "EMAIL_CONFIRM","RANDOM", "DATOS", "EXTRA", "TIME"
    USER: The username email or username name.
    NEWD: The new data.

    For edit the data, you must know the type of data.

    Example:
    EDITAR('username', 'TheUser', 'NewUser')

    return: True
    """

    try:
        if not GET_USER('username', USER) == None:
            TIPOS = ['id', 'username', 'email', 'passw', 'email_confirm', 'random', 'data_auth', 'image', 'count_view', 'permission', 'extra', 'time']
            if TYPE in TIPOS:
                recon()
                cur.execute(
                    f'UPDATE usernamedb SET {TYPE}=%s WHERE username=%s', (NEWD, USER))
                con.commit()
                con.close()
                log.info(
                    f'[EDITAR:] [OK] (type: {TYPE}, username: {USER}, data: {NEWD})')
                return 'EDITADO'
            else:
                log.debug(
                    f'[EDITAR:] [None] (type: {TYPE}, username: {USER}, data: {NEWD})')
                return 'COMPRUEBE QUE DESEA EDITAR'
        else:
            log.debug(
                f'[EDITAR:] [None] No Exist (type: {TYPE}, username: {USER}, data: {NEWD})')
            return f'EL USUARIO {USER} NO EXISTE'

    except Exception as e:
        ERROR = f'ERROR AL EDITAR\n{e}'
        log.error(f'[EDITAR:] [ERROR] (ERROR={ERROR})')
        return ERROR


def C_EMAIL_VAL(USER="", VERIFIC=False):

    try:
        numero = random.randint(100000, 999999)

        DTU = GET_USER('username', USER)

        if VERIFIC == True and DTU['email_confirm'] == "True":
            return True

        elif not DTU == None:
            recon()
            cur.execute(
                f'UPDATE usernamedb SET random=%s WHERE username=%s',(numero, USER))
            con.commit()
            con.close()
            return numero

    except Exception as e:
        ERROR = f'ERROR AL EDITAR\n{e}'
        log.error(f'[C_EMAIL_VAL:] [ERROR] (ERROR={ERROR})')
        return False


def EMAIL_VAL(EMAIL="", COD="", VERIFIC=False):

    try:
        DTU = GET_USER('email', EMAIL)
        if not DTU == None:
            DCOD = DTU["random"]
            if VERIFIC == True and DTU['email_confirm'] == "true":
                return True

            elif str(COD) == str(DCOD):
                recon()
                cur.execute(
                    f'UPDATE usernamedb SET email_confirm=%s WHERE email=%s', ('true',EMAIL))
                con.commit()
                con.close()
                return True

            else:
                recon()
                cur.execute(
                    f'UPDATE usernamedb SET email_confirm=%s WHERE email=%s', ('false',EMAIL))
                con.commit()
                con.close()
                return False
        else:
            return False

    except Exception as e:
        ERROR = f'ERROR AL EDITAR\n{e}'

        return ERROR

def COMMANDSQL(text):
    try:
        lista = []
        recon()
        for row in cur.execute(text):
            ALL = row
            lista.append(ALL)
        con.commit()
        con.close
        log.debug(f"[COMMANDSQL:] [{text}] [OK]")
        return lista
    except Exception as e:
        ERROR = f"ERROR AL EJECUTAR:\n{e}"
        log.error(f"[COMMANDSQL:] [ERROR] [{ERROR}]")
        return ERROR


def main():
    parser = argparse.ArgumentParser(description='Administra la base de datos de usuarios.')
    
    parser.add_argument('command', type=str, help='El comando a ejecutar', choices=['crearTabla', 'sql', 'insert', 'ls', 'buscar', 'encriptar', 'desencriptar', 'borrar', 'editar', 'conc', 'conv', 'help'], nargs='?')
    parser.add_argument('--user', type=str, help='Nombre de usuario para insertar o buscar')
    parser.add_argument('--email', type=str, help='Correo electrónico para insertar o validar')
    parser.add_argument('--password', type=str, help='Contraseña para insertar o encriptar')
    parser.add_argument('--sql_command', type=str, help='Comando SQL para ejecutar')
    parser.add_argument('--search_type', type=str, help='Tipo de búsqueda')
    parser.add_argument('--search_data', type=str, help='Dato para buscar')
    parser.add_argument('--text', type=str, help='Texto para encriptar o desencriptar')
    parser.add_argument('--new_info', type=str, help='Nueva información para editar')
    parser.add_argument('--code', type=str, help='Código de validación')
    
    args = parser.parse_args()

    if args.command:
        # Modo con argumentos
        if args.command == 'crearTabla':
            respuesta = CREATE_TABLE()
            print(respuesta)

        elif args.command == 'sql':
            if args.sql_command:
                resp = COMMANDSQL(args.sql_command)
                print(resp)
            else:
                print("Por favor, proporciona un comando SQL con --sql_command.")

        elif args.command == 'insert':
            if args.user and args.email and args.password:
                hashed_password = bcrypt.hashpw(args.password.encode('utf-8'), bcrypt.gensalt())
                respuesta = INSERT_USER(args.user, args.email, hashed_password.decode('utf-8'))
                print(respuesta)
            else:
                print("Por favor, proporciona usuario, correo y contraseña con --user, --email, y --password.")

        elif args.command == 'ls':
            respuesta = GET_USER('all')
            try:
                for resp in respuesta:
                    print(f'{resp}\n\n')
            except:
                print(respuesta)

        elif args.command == 'buscar':
            if args.search_type and args.search_data:
                respuesta = GET_USER(args.search_type, args.search_data)
                print(respuesta)
            else:
                print("Por favor, proporciona tipo de búsqueda y dato con --search_type y --search_data.")

        elif args.command == 'encriptar':
            if args.text and args.password:
                respuesta = ENCRIPT(args.text, args.password)
                print(respuesta)
            else:
                print("Por favor, proporciona el texto y la contraseña con --text y --password.")

        elif args.command == 'desencriptar':
            if args.text and args.password:
                respuesta = DESENCRIPT(args.text, args.password)
                print(respuesta)
            else:
                print("Por favor, proporciona el texto y la contraseña con --text y --password.")

        elif args.command == 'borrar':
            if args.user:
                respuesta = DELETE(args.user)
                print(respuesta)
            else:
                print("Por favor, proporciona el usuario a borrar con --user.")

        elif args.command == 'editar':
            if args.search_type and args.user and args.new_info:
                respuesta = EDITAR(args.search_type, args.user, args.new_info)
                print(respuesta)
            else:
                print("Por favor, proporciona tipo, usuario, y nueva información con --search_type, --user, y --new_info.")

        elif args.command == 'conc':
            if args.user:
                respuesta = C_EMAIL_VAL(args.user)
                print(respuesta)
            else:
                print("Por favor, proporciona el usuario con --user.")

        elif args.command == 'conv':
            if args.user and args.code:
                respuesta = EMAIL_VAL(args.user, args.code)
                print(respuesta)
            else:
                print("Por favor, proporciona el usuario y el código con --user y --code.")

        elif args.command == 'help':
            print("""
                Help:
                crearTabla - Crea una Tabla
                sql - Ejecuta un comando SQL
                insert - Inserta un usuario
                ls - Lista todos los usuarios
                buscar - Busca un usuario
                encriptar - Encripta un texto
                desencriptar - Desencripta un texto
                borrar - Borra un usuario
                editar - Edita un usuario
                conc - Valida un usuario por email
                conv - Valida un código de confirmación de correo
            """)
    else:
        # Modo interactivo
        print(CONNECTION_TEST())

        while True:
            entrada = str(input('\nEscribe aqui: '))

            if entrada.startswith('crearTabla'):
                respuesta = CREATE_TABLE()
                print(respuesta)
            
            elif entrada == "sql":
                texto = input("Comando: ")
                resp = COMMANDSQL(texto)
                print(resp)
            
            elif entrada == 'insert':
                valor1 = input('usuario: ')
                valor2 = input('correo: ')
                valor3 = input('contraseña: ')
                valor4 = bcrypt.hashpw(valor3.encode('utf-8'), bcrypt.gensalt())
                respuesta = INSERT_USER(valor1, valor2, valor4.decode('utf-8'))
                print(respuesta)

            elif entrada == 'ls':
                respuesta = GET_USER('all')
                try:
                    for resp in respuesta:
                        print(f'{resp}\n\n')
                except:
                    print(respuesta)
                    
            elif entrada == 'buscar':
                valor1 = input('TIPO DE BUSQUEDA: ')
                valor2 = input('DATO A BUSCAR: ')
                respuesta = GET_USER(valor1, valor2)
                print(respuesta)

            elif entrada == 'encriptar':
                valor1 = input('ESCRIBA PARA ENCRIPTAR: ')
                valor2 = input('ESCRIBA LA CONTRASEÑA PARA ENCRIPTAR: ')
                respuesta = ENCRIPT(valor1, valor2)
                print(respuesta)

            elif entrada == 'desencriptar':
                valor1 = input('ESCRIBA PARA DESENCRIPTAR: ')
                valor2 = input('ESCRIBA LA CONTRASEÑA PARA DESENCRIPTAR: ')
                respuesta = DESENCRIPT(valor1, valor2)
                print(respuesta)

            elif entrada == 'borrar':
                valor1 = input('ESCRIBA PARA BORRAR: ')
                respuesta = DELETE(valor1)
                print(respuesta)

            elif entrada == 'editar':
                valor1 = input('TIPO: ')
                valor2 = input('USUARIO: ')
                valor3 = input('INFO NEW: ')
                respuesta = EDITAR(valor1, valor2, valor3)
                print(respuesta)

            elif entrada == 'conc':
                valor1 = input('ESCRIBA PARA USUARIO: ')
                respuesta = C_EMAIL_VAL(valor1)
                print(respuesta)

            elif entrada == 'conv':
                valor1 = input('ESCRIBA PARA USUARIO: ')
                valor2 = input('ESCRIBA PARA CODIGO: ')
                respuesta = EMAIL_VAL(valor1, valor2)
                print(respuesta)

            elif entrada == 'help':
                respuesta = """
                Help:
                crearTabla - Crea una Tabla
                sql - Ejecuta un comando SQL
                insert - Inserta un usuario
                ls - Lista todos los usuarios
                buscar - Busca un usuario
                encriptar - Encripta un texto
                desencriptar - Desencripta un texto
                borrar - Borra un usuario
                editar - Edita un usuario
                conc - Valida un usuario por email
                conv - Valida un código de confirmación de correo
                """
                print(respuesta)

if __name__ == '__main__':
    main()