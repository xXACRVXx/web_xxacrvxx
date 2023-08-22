import sqlite3, jwt, datetime, cryptocode, time
import random, os


######### LOGGER ###########
import logging
try:
    import LOGGER
except:
    pass

log = logging.getLogger("DATABASE")

############################



########## EDIT ############

DB_FOLDER = "Databases"

DB_NAME = "database.db"

############################

SYSTEM_PATH = os.getcwd()

PATH = os.path.join(SYSTEM_PATH, DB_FOLDER)

PARENT_DIR = os.path.dirname(SYSTEM_PATH)

if os.path.exists(PATH) and os.path.isdir(PATH):
    DB_PATH = os.path.join(PATH, DB_NAME)
else:
    PARENT_PATH = os.path.join(PARENT_DIR, DB_FOLDER)
    if os.path.exists(PARENT_PATH) and os.path.isdir(PARENT_PATH):
        DB_PATH = os.path.join(PARENT_PATH, DB_NAME)
    else:
        os.makedirs(PATH, exist_ok=True)
        DB_PATH = os.path.join(PATH, DB_NAME)


######### connection and cursor #########
con = sqlite3.connect(DB_PATH, check_same_thread=False)

cur = con.cursor()

def recon():
    global con
    global cur
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = con.cursor()
##########################################

def CONNECTION_TEST():
    global con
    global cur
    "CONNECTION_TEST: This function is used to test the connection to the database"
    try:
        con_test = sqlite3.connect(DB_PATH)
        cur_test = con_test.cursor()
        cur_test.execute('SELECT * FROM USERDB')
        con_test.close()
        log.info("CONNECTION_TEST: OK (sqlite3)")
        return f'\nCONECTADO CORRECTAMENTE A SQLite3\n'
    except Exception as e:       
        ERROR = f"ERROR AL CONECTARSE A SQLite3:\n{e}"
        if ERROR.__contains__("Unknown database"):
            try:
                CREATE_TABLE()
                log.info("CONNECTION_TEST: OK (sqlite3)")
                return f'\nCONECTADO A SQLite3 + TABLA DE DATOS CREADAS'
            except Exception as e:
                ERROR = f"ERROR AL CONECTARSE A SQLite3:\n{e}"
                log.error(f'[CONNECTION_TEST] [ERROR 1] {ERROR}')
                return ERROR
        else:
            try:
                CREATE_TABLE()
                con = sqlite3.connect(DB_PATH, check_same_thread=False)
                cur = con.cursor()
                log.info("CONNECTION_TEST: OK (sqlite3)")
                return f'\nCONECTADO CORRECTAMENTE A SQLite3\n'
            except Exception as e:
                ERROR = f"ERROR AL CONECTARSE A SQLite3:\n{e}"
                log.error(f'[CONNECTION_TEST] [ERROR 2] {ERROR}')
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
        DATA_UNENCRYPT = jwt.decode(datos, secretkey, algorithms="HS256")
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
    """
    CREATE_TABLE()
    this function is used to create a table in the database.

    return: message with the table created.
    
    Example:
    CREATE_TABLE()
    
    return: 'TABLA DE DATOS CREADA'
    """
    try:
        recon()
        cur.execute(
            f'CREATE TABLE USERDB (ID INTEGER PRIMARY KEY AUTOINCREMENT, USER TEXT, EMAIL TEXT, PASSW TEXT, EMAIL_CONFIRM TEXT,RANDOM TEXT, DATOS TEXT, EXTRA TEXT, TIME TEXT)')
        con.close()
        log.info(f"[CREATE_TABLE:] [OK]")
        return f'TABLA DE DATOS CREADA'
    except Exception as e:
        
        ERROR = f"ERROR AL CREAR LA TABLA:\n{e}"
        if ERROR.__contains__("Unknown database"):
            try:
                recon()
                cur.execute(f'CREATE DATABASE {DB_NAME}')
                cur.execute(f'CREATE TABLE USERDB (ID INTEGER PRIMARY KEY AUTOINCREMENT, USER TEXT, EMAIL TEXT, PASSW TEXT, EMAIL_CONFIRM TEXT,RANDOM TEXT, DATOS TEXT, EXTRA TEXT, TIME TEXT)')
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


def INSERT_DB(USER='', EMAIL='', PASSW=''):
    """
    INSER_DB(USER='', EMAIL='', PASSW='')
    USER: The user name.
    EMAIL: The user email.
    PASSW: The user password.
    
    return: message with the data inserted.
    
    Example:
    INSERT_DB('user', 'email', 'passw')
    
    return: 'USUARIO CREADO CORRECTAMENTE'
    """
    try:
        comp1 = SEARCH_DB('USER', USER)
        if comp1 == None:
            comp2 = SEARCH_DB('EMAIL', EMAIL)
            if comp2 == None:
                TIME = datetime.datetime.now()
                recon()
                cur.execute(f'INSERT INTO USERDB (USER, EMAIL, PASSW, TIME)  VALUES ("{USER}", "{EMAIL}", "{PASSW}", "{TIME}")')
                con.commit()
                con.close
                log.info(f"[INSERT_DB:] [OK] (user: {USER}, email: {EMAIL}, passw: {PASSW})")
                return f'USUARIO {USER} CREADO CORRECTAMENTE'
            else:
                log.debug(f"[INSERT_DB:] [ERROR] EMAIL EXIST (user: {USER}, email: {EMAIL}, passw: {PASSW})")
                return f'EL CORREO {EMAIL} YA EXISTE'
        else:
            log.debug(f"[INSERT_DB:] [ERROR] USER EXIST (user: {USER}, email: {EMAIL}, passw: {PASSW})")
            return f'EL USUARIO {USER} YA EXISTE'
    except Exception as e:
        ERROR = f"ERROR AL INCERTAR EN LA TABLA:\n{e}"
        log.error(f"[INSERT_DB:] [ERROR] [{ERROR}] (user: {USER}, email: {EMAIL}, passw: {PASSW})")
        return ERROR

def ALL_USERS():
    """
    ALL_USERS()
    this function is used to get all the users in the database.

    return: list with all the users.
    
    Example:
    ALL_USERS()
    
    return: [
        [1, 'user', 'email', 'passw', 'email_confirm', 'random', 'datos', 'extra', 'time'],
        [2, 'user2', 'email2', 'passw2', 'email_confirm2', 'random2', 'datos2', 'extra2', 'time2'],
        [3, 'user3', 'email3', 'passw3', 'email_confirm3', 'random3', 'datos3', 'extra3', 'time3']
    ]   
    """
    try:
        lista = []
        recon()
        for row in cur.execute('SELECT * FROM USERDB'):
            ALL = row
            lista.append(ALL)
        con.close
        log.debug(f"[ALL_USERS:] [OK]")
        return lista
    except Exception as e:
        ERROR = f"ERROR AL BUSCAR TODO EN LA TABLA:\n{e}"
        log.error(f"[ALL_USERS:] [ERROR] [{ERROR}]")
        return ERROR

def SEARCH_DB(TYPE='USER', DATA_SEARCH=''):
    """
    SEARCH_DB(TYPE='USER', DATA_SEARCH='')
    TYPE: The type of data to search.
    DATA_SEARCH: The data to search. (ID, USER, EMAIL, PASSW, EMAIL_CONFIRM, RANDOM, DATOS, EXTRA, TIME)
    
    return: list with the data searched.
    
    Example:
    SEARCH_DB('USER', 'user')
    
    return: [1, 'user', 'email', 'passw', 'email_confirm', 'random', 'datos', 'extra', 'time']
    """
    try:
        recon()
        TIPOS = ["ID", "USER", "EMAIL", "PASSW", "EMAIL_CONFIRM","RANDOM", "DATOS", "EXTRA"]
        if TYPE in TIPOS:
            search_sql = f'SELECT * FROM USERDB WHERE {TYPE}="{DATA_SEARCH}"'
            cur.execute(search_sql)
            for rew in cur.fetchall():
                log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
                return rew
            con.close

        elif TYPE == 'TIME':
            lista = []
            cur.execute('SELECT * FROM USERDB')
            for row in cur.fetchall():
                ALL = row
                if ALL[8].__contains__(DATA_SEARCH):
                    lista.append(ALL)
            con.close
            log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            return lista 
        else:
            log.debug(f"[SEARCH_DB:] [None] (type: {TYPE}, data: {DATA_SEARCH})")
            return None
    except Exception as e:
        ERROR = f"ERROR AL BUSCAR EN LA TABLA:\n{e}"
        log.error(f"[SEARCH_DB:] [ERROR] [{ERROR}] (type: {TYPE}, data: {DATA_SEARCH})")
        return ERROR


def VALIDAR(US_EM, PASSW, KEY):
    """
    VALIDAR(US_EM, PASSW, KEY)
    US_EM: The user email or user name.
    PASSW: The user password.
    KEY: The key to desencrypt the password.
    
    return: True or False.
    
    Example:
    VALIDAR('user', 'passw', 'key')
    
    return: True
    """
    
    try:
        if US_EM.__contains__('@'):
            DTE = SEARCH_DB('EMAIL', US_EM)
            if not DTE == None:
                DPASSW = DESENCRIPT(DTE[3], KEY)
                if PASSW == DPASSW:
                    log.debug('[VALIDAR:] [True]')
                    return True
                else:
                    log.debug('[VALIDAR:] [False]')
                    return False
            else:
                log.debug('[VALIDAR:] [False] (SEARCH_DB=None)')
                return False
        else:
            DTU = SEARCH_DB('USER', US_EM)
            if not DTU == None:
                DPASSW = DESENCRIPT(DTU[3], KEY)
                if PASSW == DPASSW:
                    log.debug('[VALIDAR:] [True]')
                    return True
                else:
                    log.debug('[VALIDAR:] [False]')
                    return False
            else:
                log.debug('[VALIDAR:] [False] (SEARCH_DB=None)')
                return False

    except Exception as e:
        ERROR = f'ERRROR AL VALIDAR:\n{e}'
        log.error(f'[VALIDAR:] [False] (ERROR={ERROR})')
        return ERROR


def DELETE(US_EM):
    """
    DELETE(US_EM)
    US_EM: The user email or user name.
    
    return: True or False.
    
    Example:
    DELETE('user')
    
    return: True
    """
    
    try:
        if US_EM.__contains__('@'):
            if SEARCH_DB('EMAIL', US_EM) != None:
                recon()
                cur.execute(f'DELETE FROM USERDB WHERE EMAIL="{US_EM}"')
                con.commit()
                con.close()
                log.info(f'[DELETE:] [OK] (Email: {US_EM})')
                return 'EL CORREO SE HA BORRADO'
            else:
                log.debug(f'[DELETE:] [None] (Email: {US_EM})')
                return 'EL CORREO NO EXISTE '
        else:
            if SEARCH_DB('USER', US_EM) != None:
                recon()
                cur.execute(f'DELETE FROM USERDB WHERE USER="{US_EM}"')
                con.commit()
                con.close()
                log.info(f'[DELETE:] [OK] (user: {US_EM})')
                return 'EL USUARIO SE HA BORRADO'
            else:
                log.debug(f'[DELETE:] [None] (user: {US_EM})')
                return 'EL USUARIO NO EXISTE '
    except Exception as e:
        ERROR = f'ERROR AL BORRAR:\n{e}'
        log.error(f'[DELETE:] [ERROR] (ERROR={ERROR})')
        return ERROR


def EDITAR(TYPE='USER', USER='', NEWD=''):
    """
    TYPE: "ID", "USER", "EMAIL", "PASSW", "EMAIL_CONFIRM","RANDOM", "DATOS", "EXTRA", "TIME"
    USER: The user email or user name.
    NEWD: The new data.
    
    For edit the data, you must know the type of data.
    
    Example:
    EDITAR('USER', 'TheUser', 'NewUser')
    
    return: True
    """

    try:
        if not SEARCH_DB('USER', USER) == None:
            TIPOS = ["ID", "USER", "EMAIL", "PASSW", "EMAIL_CONFIRM","RANDOM", "DATOS", "EXTRA", "TIME"]
            if TYPE in TIPOS:
                recon()
                cur.execute(f'UPDATE USERDB SET {TYPE}="{NEWD}" WHERE USER="{USER}"')               
                con.commit()               
                con.close()
                log.info(f'[EDITAR:] [OK] (type: {TYPE}, user: {USER}, data: {NEWD})')
                return 'EDITADO'
            else:
                log.debug(f'[EDITAR:] [None] (type: {TYPE}, user: {USER}, data: {NEWD})')
                return 'COMPRUEBE QUE DESEA EDITAR'
        else:
            log.debug(f'[EDITAR:] [None] No Exist (type: {TYPE}, user: {USER}, data: {NEWD})')
            return f'EL USUARIO {USER} NO EXISTE'

    except Exception as e:
        ERROR = f'ERROR AL EDITAR\n{e}'
        log.error(f'[EDITAR:] [ERROR] (ERROR={ERROR})')
        return ERROR

def C_EMAIL_VAL(USER=""):

    try:
        numero = random.randint(100000, 999999)

        if not SEARCH_DB('USER', USER) == None:
            recon()
            cur.execute(f'UPDATE USERDB SET RANDOM="{str(numero)}" WHERE USER="{USER}"')
            con.commit()
            con.close()
            return numero
        
    except Exception as e:
        ERROR = f'ERROR AL EDITAR\n{e}'

        return ERROR

def EMAIL_VAL(EMAIL="", COD=""):
    
    try:
        DTU = SEARCH_DB('EMAIL', EMAIL)
        if not DTU == None:
            DCOD = DTU[5]
            # print(DPASSW)
            if COD == DCOD:
                recon()
                cur.execute(f'UPDATE USERDB SET EMAIL_CONFIRM="True" WHERE EMAIL="{EMAIL}"')
                con.commit()
                con.close()
                return True
            else:
                recon()
                cur.execute(f'UPDATE USERDB SET EMAIL_CONFIRM="False" WHERE EMAIL="{EMAIL}"')
                con.commit()
                con.close()
                return False

    except Exception as e:
        ERROR = f'ERROR AL EDITAR\n{e}'

        return ERROR


if __name__ == '__main__':
    
    print(CONNECTION_TEST())
    existe = os.path.isfile(DB_PATH)
    if existe == True:
        print("RUTA =",DB_PATH)
    else:
        print(f"ERROR: LA RUTA ={DB_PATH} NO EXISTE")

    while True:
        entrada = str(input('\nEscribe aqui: '))

        if entrada.startswith('crearTabla'):
            respuesta = CREATE_TABLE()
            print(respuesta)

        if entrada == 'insert':
            valor1 = input('usuario: ')
            valor2 = input('correo: ')
            valor3 = input('contraseña: ')
            valor4 = input('db_passw: ')
            valor5 = ENCRIPT(valor3, valor4)
            respuesta = INSERT_DB(valor1, valor2, valor5)
            print(respuesta)

        if entrada == 'ls':
            respuesta = ALL_USERS()
            res2 = datetime.datetime.now()
            print(respuesta)

        if entrada == 'buscar':
            valor1 = input('TIPO DE BUSQUEDA: ')
            valor2 = input('DATO A BUSCAR: ')
            respuesta = SEARCH_DB(valor1, valor2)
            print(respuesta)

        if entrada == 'encriptar':
            valor1 = input('ESCRIBA PARA ENCTIPTAR: ')
            valor2 = input('ESCRIBA LA CONTRASEÑA PARA ENCRIPTAR: ')
            respuesta = ENCRIPT(valor1, valor2)
            print(respuesta)

        if entrada == 'desencriptar':
            valor1 = input('ESCRIBA PARA DESENCTIPTAR: ')
            valor2 = input('ESCRIBA LA CONTRASEÑA PARA DESENCRIPTAR: ')
            respuesta = DESENCRIPT(valor1, valor2)
            print(respuesta)

        if entrada == 'validar':
            valor1 = input('ESCRIBA EL USER/EMAIL PARA VALIDAR: ')
            valor2 = input('ESCRIBA LA CONTRASEÑA PARA VALIDAR: ')
            valor3 = input('db_passw: ')
            respuesta = VALIDAR(valor1, valor2, valor3)
            print(respuesta)

        if entrada == 'borrar':
            valor1 = input('ESCRIBA PARA BORRAR: ')
            respuesta = DELETE(valor1)

            print(respuesta)

        if entrada == 'editar':
            valor1 = input('TIPO: ')
            valor2 = input('USUARIO: ')
            valor3 = input('INFO NEW: ')
            respuesta = EDITAR(valor1, valor2, valor3)
            print(respuesta)

        if entrada == 'conc':
            valor1 = input('ESCRIBA PARA USUARIO: ')
            respuesta = C_EMAIL_VAL(valor1)

            print(respuesta)

        if entrada == 'conv':
            valor1 = input('ESCRIBA PARA USUARIO: ')
            valor2 = input('ESCRIBA PARA CODIGO: ')
            respuesta = EMAIL_VAL(valor1, valor2)
            
            print(respuesta)
            
        if entrada == 'help':
            
            respuesta = """
            Help:
            crearTabla Crea una Tabla
            insert Inserta un usuario
            ls Lista todos los usuarios
            buscar Busca un usuario
            encriptar Encripta un texto
            desencriptar Desencripta un texto
            validar Valida un usuario
            borrar Borra un usuario
            editar Edita un usuario
            conv valida un codigo de confirmacion de correo
            """

            print(respuesta)