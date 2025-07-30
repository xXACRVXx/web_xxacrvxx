from psycopg.rows import dict_row
import psycopg
import re
import datetime
import traceback
import os
import markdown
import argparse
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
try:
    con = psycopg.connect(DB_PATH, row_factory=dict_row)
    cur = con.cursor()
except Exception as e:
    log.error(f'[CONNECTION] [ERROR] {e}')
    traceback.print_exc()
def recon():
    try:
        global con
        global cur
        con = psycopg.connect(DB_PATH, row_factory=dict_row)
        cur = con.cursor()
    except Exception as e:
        log.error(f'[CONNECTION] [ERROR] {e}')
##########################################


def CONNECTION_TEST():
    "CONNECTION_TEST: This function is used to test the connection to the database"
    try:
        cur.execute('SELECT * FROM blogpg')
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
        cur.execute(EXECREATE)
        con.commit()
        log.info(f"[CREATE_TABLE:] [OK]")
        return f'TABLA DE DATOS CREADA'
    except Exception as e:
        ERROR = f"ERROR AL CREAR LA TABLA:\n{e}"
        if ERROR.__contains__("Unknown database"):
            try:
                cur.execute(f'CREATE DATABASE {DB_NAME}')
                cur.execute(EXECREATE)
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
            cur.execute('INSERT INTO blogpg (title, descript, content, creat_id, image, count_view, tags, category, time)  VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)', (TITLE, DESCRIP, CONTENT, CREAT_ID, IMAGE, COUNT_VIEW, TAGS, CATEGORY, str(TIME)))
            con.commit()
            log.info(f"[INSERT_DB:] [OK] (Title: {TITLE}, Content: {CONTENT}, Create_by: {CREAT_ID}, TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
            return f'ENTRADA {TITLE} CREADA CORRECTAMENTE'
        else:
            log.debug(f"[INSERT_DB:] [ERROR] TITLE EXIST (Title: {TITLE}, Content: {CONTENT}, Create_by: {CREAT_ID},  TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
            return f'EL TITULO {TITLE} YA EXISTE'
    except Exception as e:
        ERROR = f"ERROR AL INCERTAR EN LA TABLA:\n{e}"
        log.error(
            f"[INSERT_DB:] [ERROR] [{ERROR}] (Title: {TITLE}, Content: {CONTENT}, Create_by: {CREAT_ID}, TAGS: {TAGS}, DESCRIPTION: {DESCRIP})")
        return ERROR



def GET_BL(TYPE='title', DATA_SEARCH='', MARKDOWN=True, UID=True, SUM_VIEW=False, TAGS=True):
    try:
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
                    row['tags'] = row['tags'].split(',') if row['tags'] else []
                # Procesar categoría de forma similar a tags
                if row.get('category'):
                    row['category'] = row['category'].split(',') if ',' in str(row['category']) else [row['category']]
                else:
                    row['category'] = []
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
                row['tags'] = row['tags'].split(',') if row['tags'] else []
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
                row['tags'] = row['tags'].split(',') if row['tags'] else []
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
                row['tags'] = row['tags'].split(',') if row['tags'] else []
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
            cur.execute('DELETE FROM blogpg WHERE id= %s',(B_ID,))
            con.commit()
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
                cur.execute(
                    f'UPDATE blogpg SET {TYPE}=%s WHERE id=%s', (NEWD, B_ID))
                con.commit()
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
        for row in cur.execute(text):
            ALL = row
            lista.append(ALL)
        con.commit()
        log.debug(f"[COMMANDSQL:] [{text}] [OK]")
        return lista
    except Exception as e:
        ERROR = f"ERROR AL EJECUTAR:\n{e}"
        log.error(f"[COMMANDSQL:] [ERROR] [{ERROR}]")
        return ERROR

def main():
    parser = argparse.ArgumentParser(description='Administra la base de datos de blog.')
    
    parser.add_argument('command', type=str, help='El comando a ejecutar', choices=['crearTabla', 'sql', 'insert', 'ls', 'buscar', 'borrar', 'editar', 'help'], nargs='?')
    parser.add_argument('--titulo', type=str, help='Título del blog')
    parser.add_argument('--descripcion', type=str, help='Descripción del blog')
    parser.add_argument('--contenido', type=str, help='Contenido del blog')
    parser.add_argument('--autor_id', type=str, help='ID del autor del blog')
    parser.add_argument('--imagen', type=str, help='Imagen del blog')
    parser.add_argument('--tags', type=str, help='Tags del blog')
    parser.add_argument('--categoria', type=str, help='Categoría del blog')
    parser.add_argument('--sql_command', type=str, help='Comando SQL para ejecutar')
    parser.add_argument('--search_type', type=str, help='Tipo de búsqueda')
    parser.add_argument('--search_data', type=str, help='Dato para buscar')
    parser.add_argument('--blog_id', type=str, help='ID del blog para editar o borrar')
    parser.add_argument('--new_info', type=str, help='Nueva información para editar')
    
    args = parser.parse_args()

    if args.command:
        # Modo con argumentos
        if args.command == 'crearTabla':
            resp = CREATE_TABLE()
            print(f'{resp}\n\n')

        elif args.command == 'sql':
            if args.sql_command:
                resp = COMMANDSQL(args.sql_command)
                print(f'{resp}\n\n')
            else:
                print("Por favor, proporciona un comando SQL con --sql_command.")

        elif args.command == 'insert':
            if args.titulo and args.descripcion and args.contenido and args.autor_id:
                resp = INSERT_BL(args.titulo, args.descripcion, args.contenido, args.autor_id, args.imagen, args.tags, args.categoria)
                print(f'{resp}\n\n')
            else:
                print("Por favor, proporciona título, descripción, contenido y autor_id con --titulo, --descripcion, --contenido, y --autor_id.")

        elif args.command == 'ls':
            respuesta = GET_BL('all', MARKDOWN=False, UID=False)
            try:
                for resp in respuesta:
                    print(f'{resp}\n\n')
            except:
                print(respuesta)

        elif args.command == 'buscar':
            if args.search_type and args.search_data:
                respuesta = GET_BL(args.search_type, args.search_data, MARKDOWN=False, UID=False)
                try:
                    for resp in respuesta:
                        print(f'{resp}\n\n')
                except:
                    print(respuesta)
            else:
                print("Por favor, proporciona tipo de búsqueda y dato con --search_type y --search_data.")

        elif args.command == 'borrar':
            if args.blog_id:
                resp = DELETE_BL(args.blog_id)
                print(f'{resp}\n\n')
            else:
                print("Por favor, proporciona el ID del blog con --blog_id.")

        elif args.command == 'editar':
            if args.search_type and args.blog_id and args.new_info:
                resp = EDIT_BL(args.search_type, args.blog_id, args.new_info)
                print(f'{resp}\n\n')
            else:
                print("Por favor, proporciona tipo, ID, y nueva información con --search_type, --blog_id, y --new_info.")

        elif args.command == 'help':
            print("""
            Help:
            crearTabla - Crea una Tabla
            sql - Ejecuta un comando SQL
            insert - Inserta un blog
            ls - Lista todos los blogs
            buscar - Busca un blog
            borrar - Borra un blog
            editar - Edita un blog
            """)

    else:
        # Modo interactivo
        print(CONNECTION_TEST())
        while True:
            entrada = str(input('\nEscribe aqui: '))

            if entrada.startswith('crearTabla'):
                resp = CREATE_TABLE()
                print(f'{resp}\n\n')
            
            elif entrada == "sql":
                texto = input("Comando: ")
                resp = COMMANDSQL(texto)
                print(f'{resp}\n\n')
            
            elif entrada == 'insert':
                valor1 = input('TITULO: ')
                valor2 = input('DESCRIPCION: ')
                valor3 = input('CONTENIDO: ')
                valor4 = input('AUTOR_ID: ')
                valor5 = input('IMAGEN: ')
                valor6 = input('TAGS: ')
                valor7 = input('CATEGORIA: ')
                resp = INSERT_BL(valor1, valor2, valor3, valor4, valor5, valor6, valor7)
                print(f'{resp}\n\n')

            elif entrada == 'ls':
                respuesta = GET_BL('all', MARKDOWN=False, UID=False)
                try:
                    for resp in respuesta:
                        print(f'{resp}\n\n')
                except:
                    print(respuesta)

            elif entrada == 'buscar':
                valor1 = input('TIPO DE BUSQUEDA: ')
                valor2 = input('DATO A BUSCAR: ')
                respuesta = GET_BL(valor1, valor2, MARKDOWN=False, UID=False)
                try:
                    for resp in respuesta:
                        print(f'{resp}\n\n')
                except:
                    print(respuesta)

            elif entrada == 'borrar':
                valor1 = input('ESCRIBA ID PARA BORRAR: ')
                resp = DELETE_BL(valor1)
                print(f'{resp}\n\n')

            elif entrada == 'editar':
                valor1 = input('TIPO: ')
                valor2 = input('ID: ')
                valor3 = input('INFO NEW: ')
                resp = EDIT_BL(valor1, valor2, valor3)
                print(f'{resp}\n\n')

            elif entrada == 'help':
                respuesta = """
                Help:
                crearTabla - Crea una Tabla
                insert - Inserta un blog
                ls - Lista todos los blogs
                buscar - Busca un blog
                borrar - Borra un blog
                editar - Edita un blog
                """
                print(respuesta)

if __name__ == '__main__':
    main()