import os, traceback
import platform
import psutil
import logging
from dotenv import load_dotenv

load_dotenv("config.env") # carga las variables de entorno desde el archivo .env

log = logging.getLogger("CONFIG")

SECRECT = os.getenv("SECRET_KEY")



MY_OS = platform.system()
SYSTEM_PATH = os.getcwd()

DOWLOAD_PATH = "Downloads"


RUTE = os.path.join(SYSTEM_PATH,DOWLOAD_PATH)



def Free_Space():
    disk_usage = psutil.disk_usage(SYSTEM_PATH)
    disk_space = disk_usage.free / 1024**2
    if disk_space >= 1024:
        the_space = round(disk_space / 1024, 2)
        return f"{the_space}GB"
    else:
        the_space = round(disk_space, 2)
        return f"{the_space}MB"




def SPACE_FILE(uss,archive):
    try:
        rute_archive = os.path.join(RUTE,str(uss),str(archive))
        the_file=os.path.getsize((rf'{rute_archive}'))
        f_space = the_file / 1024**2
        if the_file / 1024**1 <= 1024:
            the_space_file = round(the_file / 1024**1, 2)
            return f"{the_space_file}KB"
        elif f_space >= 1024:
            the_space_file = round(f_space / 1024, 2)
            return f"{the_space_file}GB"
        else:
            the_space_file = round(f_space, 2)
            return f"{the_space_file}MB"
    except Exception as e:
        log.error(f"[SPACE_FILE] [ERROR] {e} [{traceback.format_exc()}]")
        return "ERROR"
        






if __name__ == "__main__":
    print(f"SISTEMA OPERATIVO: {MY_OS}")
    print(f"RUTA DEL PATH DEL SERVIDOR: {RUTE}")
    print(f"ESPACIO DISPONIBLE  {Free_Space()}")
