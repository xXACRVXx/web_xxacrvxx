import re
import sqlite3
import datetime
import traceback
import os
import markdown
try:
    from Modules.TOOLSQL import SEARCH_DB
except:
    try:
        from TOOLSQL import SEARCH_DB
    except:
        pass   

######### LOGGER ###########
import logging
try:
    import LOGGER
except:
    pass

log = logging.getLogger("BLOGDB")

############################


########## EDIT ############

DB_FOLDER = "Databases"

DB_NAME = "blogdb.db"

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
con.row_factory = sqlite3.Row
cur = con.cursor()


def recon():
    global con
    global cur
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
##########################################


def CONNECTION_TEST():
    global con
    global cur
    "CONNECTION_TEST: This function is used to test the connection to the database"
    try:
        con_test = sqlite3.connect(DB_PATH, check_same_thread=False)
        con.row_factory = sqlite3.Row
        cur_test = con_test.cursor()
        cur_test.execute('SELECT * FROM USERDB')
        con_test.close()
        log.info("CONNECTION_TEST: OK (sqlite3) ")
        return f'\nCONECTADO CORRECTAMENTE A SQLite3\n'
    except Exception as e:
        ERROR = f"ERROR AL CONECTARSE A SQLite3:\n{e}"
        try:
            CREATE_TABLE()
            log.info("CONNECTION_TEST: OK (sqlite3)")
            return f'\nCONECTADO A SQLite3 + TABLA DE DATOS CREADAS'
        except Exception as e:
            ERROR = f"ERROR AL CONECTARSE A SQLite3:\n{e}"
            log.error(f'[CONNECTION_TEST] [ERROR 1] {ERROR}')
            return ERROR


def CREATE_TABLE():    
    EXECREATE = 'CREATE TABLE BLOGDB (ID INTEGER PRIMARY KEY AUTOINCREMENT, TITLE TEXT, CONTENT TEXT, C_BY TEXT, TAGS TEXT, PERMISSION TEXT, EXTRA TEXT, TIME TEXT)'
    try:
        recon()    
        cur.execute(EXECREATE)
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


def INSERT_BL(TITLE='', CONTENT='', C_BY='', TAGS=None, DESCRIP=None):
    try:
        comp1 = GET_BL('TITLE', TITLE)
        if comp1 == None:
            TIME = datetime.datetime.now()
            recon()
            cur.execute(
                f'INSERT INTO BLOGDB (TITLE, CONTENT, C_BY, TAGS, EXTRA, TIME)  VALUES (?, ?, ?, ?, ?, ?)', (TITLE, CONTENT, C_BY, TAGS, DESCRIP, TIME))
            con.commit()
            con.close
            log.info(
                f"[INSERT_DB:] [OK] (Title: {TITLE}, Content: {CONTENT}, Create_by: {C_BY}, TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
            return f'ENTRADA {TITLE} CREADA CORRECTAMENTE'

        else:
            log.debug(
                f"[INSERT_DB:] [ERROR] TITLE EXIST (Title: {TITLE}, Content: {CONTENT}, Create_by: {C_BY},  TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
            return f'EL TITULO {TITLE} YA EXISTE'
    except Exception as e:
        ERROR = f"ERROR AL INCERTAR EN LA TABLA:\n{e}"
        log.error(
            f"[INSERT_DB:] [ERROR] [{ERROR}] (Title: {TITLE}, Content: {CONTENT}, Create_by: {C_BY}, TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
        return ERROR



def GET_BL(TYPE='TITLE', DATA_SEARCH=''):
    try:
        recon()
        TIPOS = ["ID", "TITLE", "CONTENT", "C_BY", "TAGS", "PERMISSION", "EXTRA"]
        if TYPE in TIPOS:
            cur.execute(f'SELECT * FROM BLOGDB WHERE {TYPE}= ?', (DATA_SEARCH,))
            resp = []
            for row in cur.fetchall():
                row = dict(row)
                row['CONTENT'] =  markdown.markdown(row['CONTENT'])
                row['TAGS'] = row['TAGS'].split(',')
                try:
                    row['C_BY'] = SEARCH_DB('ID', row['C_BY'])[1]
                except:
                    row['C_BY'] = 'unknown'
                row['CONTENT'] = re.sub(r'(<img\s+)([^>]*)(>)', r'\1class="card-img-top" \2\3', row['CONTENT'])
                resp.append(row)
            log.debug(
                f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            con.close()
            if len(resp) == 0:
                return None
            return resp  
        elif TYPE == 'TIME':
            lista = []
            cur.execute('SELECT * FROM BLOGDB')
            for row in cur.fetchall():
                row = dict(row)
                row['CONTENT'] =  markdown.markdown(row['CONTENT'])
                row['TAGS'] = row['TAGS'].split(',')
                try:
                    row['C_BY'] = SEARCH_DB('ID', row['C_BY'])[1]
                except:
                    row['C_BY'] = 'unknown'  
                ALL = row
                if ALL['TIME'].__contains__(DATA_SEARCH):
                    lista.append(ALL)
            con.close
            log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            return lista
        elif TYPE == 'ALL':
            lista = []
            for row in cur.execute('SELECT * FROM BLOGDB'):
                row = dict(row)
                row['CONTENT'] =  markdown.markdown(row['CONTENT'])
                row['TAGS'] = row['TAGS'].split(',')
                try:
                    row['C_BY'] = SEARCH_DB('ID', row['C_BY'])[1]
                except:
                    row['C_BY'] = 'unknown'           
                lista.append(row)
            con.close
            return lista  
        else:
            log.debug(
                f"[SEARCH_DB:] [None] (type: {TYPE}, data: {DATA_SEARCH})")
            return None
    except Exception as e:
        ERROR = f"ERROR AL BUSCAR EN LA TABLA:\n{e}"
        log.error(
            f"[SEARCH_DB:] [ERROR] [{ERROR}] (type: {TYPE}, data: {DATA_SEARCH}) [{traceback.format_exc()}]")
        return ERROR


def DELETEBL(B_ID):
    try:
        if GET_BL('ID', B_ID) != None:
            recon()
            cur.execute(f'DELETE FROM BLOGDB WHERE ID=?',(B_ID,))
            con.commit()
            con.close()
            log.info(f'[DELETEBL:] [OK] (ID: {B_ID})')
            return True
        else:
            log.debug(f'[DELETEBL:] [None] (ID: {B_ID})')
            return False
    except Exception as e:
        ERROR = f'ERROR AL BORRAR:\n{e}'
        log.error(f'[DELETEBL:] [ERROR] (ERROR={ERROR})')
        return ERROR


def EDITBL(TYPE='TITLE', B_ID='', NEWD=''):
    try:
        if not GET_BL('ID', B_ID) == None:
            TIPOS = ["ID", "TITLE", "CONTENT", "C_BY", "TAGS", "PERMISSION", "EXTRA", "TIME"]
            if TYPE in TIPOS:
                recon()
                cur.execute(
                    f'UPDATE BLOGDB SET {TYPE}=? WHERE ID=?', (NEWD, B_ID))
                con.commit()
                con.close()
                log.info(
                    f'[EDITARBL:] [OK] (type: {TYPE}, id: {B_ID}, data: {NEWD})')
                return True
            else:
                log.debug(
                    f'[EDITARBL:] [None] (type: {TYPE}, id: {B_ID}, data: {NEWD})')
                return False
        else:
            log.debug(
                f'[EDITARBL:] [None] No Exist (type: {TYPE}, id: {B_ID}, data: {NEWD})')
            return False

    except Exception as e:
        ERROR = f'ERROR AL EDITAR\n{e}'
        log.error(f'[EDITARBL:] [ERROR] (ERROR={ERROR})')
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


if __name__ == '__main__':

    print(CONNECTION_TEST())
    existe = os.path.isfile(DB_PATH)
    if existe == True:
        print("RUTA =", DB_PATH)
    else:
        print(f"ERROR: LA RUTA ={DB_PATH} NO EXISTE")

    while True:
        entrada = str(input('\nEscribe aqui: '))

        if entrada.startswith('crearTabla'):
            respuesta = CREATE_TABLE()
            for resp in respuesta:
                print(f'{resp}\n\n')
        
        if entrada == "sql":
            texto = input("Comando: ")
            resp = COMMANDSQL(texto)
            for resp in respuesta:
                print(f'{resp}\n\n')
        
        if entrada == 'insert':
            valor1 = input('TITULO: ')
            valor2 = input('CONTENIDO: ')
            valor3 = input('ID CREADOR: ')
            respuesta = INSERT_BL(valor1, valor2, valor3)
            for resp in respuesta:
                print(f'{resp}\n\n')

        if entrada == 'ls':
            respuesta = GET_BL('ALL')
            for resp in respuesta:
                print(f'{resp}\n\n')

        if entrada == 'buscar':
            valor1 = input('TIPO DE BUSQUEDA: ')
            valor2 = input('DATO A BUSCAR: ')
            respuesta = GET_BL(valor1, valor2)
            for resp in respuesta:
                print(f'{resp}\n\n')

        if entrada == 'borrar':
            valor1 = input('ESCRIBA PARA BORRAR: ')
            respuesta = DELETEBL(valor1)
            for resp in respuesta:
                print(f'{resp}\n\n')

        if entrada == 'editar':
            valor1 = input('TIPO: ')
            valor2 = input('USUARIO: ')
            valor3 = input('INFO NEW: ')
            respuesta = EDITBL(valor1, valor2, valor3)
            for resp in respuesta:
                print(f'{resp}\n\n')

        if entrada == 'help':
            respuesta = """
            Help:
            crearTabla Crea una Tabla
            insert Inserta un usuario
            ls Lista todos los usuarios
            buscar Busca un usuario
            borrar Borra un usuario
            editar Edita un usuario
            """
            print(respuesta)
