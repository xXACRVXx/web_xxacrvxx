from psycopg.rows import dict_row
import psycopg
import re
import datetime
import traceback
import os
import markdown
from dotenv import load_dotenv
try:
    from Modules.USERPG import GET_USER
except:
    try:
        from USERPG import GET_USER
    except:
        pass   

######### LOGGER ###########
import logging
try:
    import LOGGER
except:
    pass

log = logging.getLogger("BLOGPG")

############################


########## EDIT ############
load_dotenv("config.env") # carga las variables de entorno desde el archivo .env

HOST = os.getenv("HOST_DB")
PORT = os.getenv("PORT_DB")
DB_NAME = os.getenv("NAME_DB")
USERPG = os.getenv("USERPG_DB")
PASSWPG = os.getenv("PASSWPG_DB")

DB_PATH = f"postgresql://{USERPG}:{PASSWPG}@{HOST}:{PORT}/{DB_NAME}"
#DB_PATH = f"host={HOST} port={PORT} dbname={DB_NAME} user={USERPG} password={PASSWPG}"
############################


######### connection and cursor #########
con = psycopg.connect(DB_PATH, row_factory=dict_row)
cur = con.cursor()


def recon():
    global con
    global cur
    con = psycopg.connect(DB_PATH, row_factory=dict_row)
    cur = con.cursor()
##########################################


def CONNECTION_TEST():
    global con
    global cur
    "CONNECTION_TEST: This function is used to test the connection to the database"
    try:
        con_test = psycopg.connect(DB_PATH)
        cur_test = con_test.cursor()
        cur_test.execute('SELECT * FROM blogpg')
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


def CREATE_TABLE():    
    EXECREATE = 'CREATE TABLE IF NOT EXISTS blogpg (id SERIAL PRIMARY KEY, title text, descript text, content text, creat_id integer, tags text, category text, image text, count_view integer, permission text, extra text, time text)'
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


def INSERT_BL(TITLE='', DESCRIP='', CONTENT='', CREAT_ID='', IMAGE=None, TAGS=None, CATEGORY=None, COUNT_VIEW=0):
    try:
        comp1 = GET_BL('title', TITLE)
        if comp1 == None:
            TIME = datetime.datetime.now()
            recon()
            cur.execute(
                'INSERT INTO blogpg (title, descript, content, creat_id, image, count_view, tags, category, time)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)', (TITLE, DESCRIP, CONTENT, CREAT_ID, IMAGE, COUNT_VIEW, TAGS, CATEGORY, str(TIME)))
            con.commit()
            con.close
            log.info(
                f"[INSERT_DB:] [OK] (Title: {TITLE}, Content: {CONTENT}, Create_by: {CREAT_ID}, TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
            return f'ENTRADA {TITLE} CREADA CORRECTAMENTE'

        else:
            log.debug(
                f"[INSERT_DB:] [ERROR] TITLE EXIST (Title: {TITLE}, Content: {CONTENT}, Create_by: {CREAT_ID},  TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
            return f'EL TITULO {TITLE} YA EXISTE'
    except Exception as e:
        ERROR = f"ERROR AL INCERTAR EN LA TABLA:\n{e}"
        log.error(
            f"[INSERT_DB:] [ERROR] [{ERROR}] (Title: {TITLE}, Content: {CONTENT}, Create_by: {CREAT_ID}, TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
        return ERROR



def GET_BL(TYPE='title', DATA_SEARCH='', MARKDOWN=True, UID=True, SUM_VIEW=False, TAGS=True):
    try:
        recon()
        TIPOS = ["id", "descript", "title", "content", "creat_id", "category", "image", "count_view", "permission", "extra"]
        users = GET_USER('all')
        if TYPE in TIPOS:
            cur.execute(f'SELECT * FROM blogpg WHERE {TYPE}= %s', (DATA_SEARCH,))
            resp = []
            for row in cur.fetchall():
                row = dict(row)
                if MARKDOWN:
                    row['content'] =  markdown.markdown(row['content'])
                if TAGS:
                    row['tags'] = row['tags'].split(',')
                row['content'] = re.sub(r'(<img\s+)([^>]*)(>)', r'\1class="card-img-top" style="aspect-ratio: 10/8;object-fit: contain;"\2\3', row['content'])
                if UID:
                    try:
                        for user in users:
                            if user['id'] == row['creat_id']:
                                row['creat_id'] = user['username']
                        if type(row['creat_id']) == int:
                            row['creat_id'] = 'unknown'
                    except:
                        row['creat_id'] = 'unknown'
                if SUM_VIEW:
                    row['count_view'] = int(row['count_view']) + 1
                resp.append(row)
            log.debug(
                f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            con.close()
            if len(resp) == 0:
                return None
            return resp  
        elif TYPE == 'time':
            resp = []
            cur.execute('SELECT * FROM blogpg')
            for row in cur.fetchall():
                row = dict(row)
                if MARKDOWN:
                    row['content'] =  markdown.markdown(row['content'])
                row['tags'] = row['tags'].split(',')
                if UID:
                    try:
                        for user in users:
                            if user['id'] == row['creat_id']:
                                row['creat_id'] = user['username']
                        if type(row['creat_id']) == int:
                            row['creat_id'] = 'unknown'
                    except:
                        row['creat_id'] = 'unknown'
                if row['time'].__contains__(DATA_SEARCH):
                    resp.append(row)
            con.close
            log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            if len(resp) == 0:
                return None
            return resp
        elif TYPE == 'tags':
            resp = []
            cur.execute('SELECT * FROM blogpg')
            for row in cur.fetchall():
                row = dict(row)
                if MARKDOWN:
                    row['content'] =  markdown.markdown(row['content'])
                row['tags'] = row['tags'].split(',')
                if UID:
                    try:
                        for user in users:
                            if user['id'] == row['creat_id']:
                                row['creat_id'] = user['username']
                        if type(row['creat_id']) == int:
                            row['creat_id'] = 'unknown'
                    except:
                        row['creat_id'] = 'unknown'  
                if DATA_SEARCH in row['tags']:
                    resp.append(row)
            con.close
            log.debug(f"[SEARCH_DB:] [OK] (type: {TYPE}, data: {DATA_SEARCH})")
            if len(resp) == 0:
                return None
            return resp
        elif TYPE == 'all':
            resp = []
            for row in cur.execute('SELECT * FROM blogpg'):
                row = dict(row)
                if MARKDOWN:
                    row['content'] =  markdown.markdown(row['content'])
                row['tags'] = row['tags'].split(',')
                if UID:
                    try:
                        for user in users:
                            if user['id'] == row['creat_id']:
                                row['creat_id'] = user['username']
                        if type(row['creat_id']) == int:
                            row['creat_id'] = 'unknown'
                    except:
                        row['creat_id'] = 'unknown'
                resp.append(row)
            con.close
            if len(resp) == 0:
                return None
            return resp
        else:
            log.debug(
                f"[SEARCH_DB:] [None] (type: {TYPE}, data: {DATA_SEARCH})")
            return None
    except Exception as e:
        ERROR = f"ERROR AL BUSCAR EN LA TABLA:\n{e}"
        log.error(
            f"[SEARCH_DB:] [ERROR] [{ERROR}] (type: {TYPE}, data: {DATA_SEARCH}) [{traceback.format_exc()}]")
        return ERROR


def DELETE_BL(B_ID):
    try:
        if GET_BL('id', B_ID) != None:
            recon()
            cur.execute('DELETE FROM blogpg WHERE id= %s',(B_ID,))
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


def EDIT_BL(TYPE='title', B_ID='', NEWD=''):
    try:
        if not GET_BL('id', B_ID) == None:
            TIPOS = ["id", "descript", "title", "content", "creat_id", "tags", "category", "image", "count_view", "permission", "extra", "time"]
            if TYPE in TIPOS:
                recon()
                cur.execute(
                    f'UPDATE blogpg SET {TYPE}=%s WHERE id=%s', (NEWD, B_ID))
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
    while True:
        entrada = str(input('\nEscribe aqui: '))

        if entrada.startswith('crearTabla'):
            resp = CREATE_TABLE()
            print(f'{resp}\n\n')
        
        if entrada == "sql":
            texto = input("Comando: ")
            resp = COMMANDSQL(texto)
            for resp in respuesta:
                print(f'{resp}\n\n')
        
        if entrada == 'insert':
            valor1 = input('TITULO: ')
            valor2 = input('DESCRIPCION: ')
            valor3 = input('CONTENIDO: ')
            valor4 = input('AUTOR_ID: ')
            valor5 = input('IMAGEN: ')
            valor6 = input('TAGS: ')
            valor7 = input('CATEGORIA: ')
            resp = INSERT_BL(valor1, valor2, valor3, valor4, valor5, valor6, valor7)
            print(f'{resp}\n\n')

        if entrada == 'ls':
            respuesta = GET_BL('all', MARKDOWN=False, UID=False)
            try:
                for resp in respuesta:
                    print(f'{resp}\n\n')
            except:
                print(respuesta)

        if entrada == 'buscar':
            valor1 = input('TIPO DE BUSQUEDA: ')
            valor2 = input('DATO A BUSCAR: ')
            respuesta = GET_BL(valor1, valor2, MARKDOWN=False, UID=False)
            try:
                for resp in respuesta:
                    print(f'{resp}\n\n')
            except:
                print(respuesta)

        if entrada == 'borrar':
            valor1 = input('ESCRIBA ID PARA BORRAR: ')
            resp = DELETE_BL(valor1)
            print(f'{resp}\n\n')

        if entrada == 'editar':
            valor1 = input('TIPO: ')
            valor2 = input('ID: ')
            valor3 = input('INFO NEW: ')
            resp = EDIT_BL(valor1, valor2, valor3)
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
