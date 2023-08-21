from dotenv import load_dotenv
import logging
import os
import sys
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from termcolor import colored


load_dotenv("config.env") # carga las variables de entorno desde el archivo .env
DEBUG = os.getenv("DEBUG") == "True"

LOGS_DIR = "logs"

class CustomFormatter(logging.Formatter):
    def __init__(self, no_colors: bool = False):
        super().__init__()
        self.no_colors = no_colors

        self.FORMATS = {
            logging.DEBUG: "%(levelname)s",
            logging.INFO: colored("%(levelname)s", "blue"),
            logging.WARN: colored("%(levelname)s", "yellow"),
            logging.ERROR: colored("%(levelname)s", "red"),
            logging.CRITICAL: colored("%(levelname)s", "red", None, ["bold"]),
        }

    def format(self, record: logging.LogRecord):
        time = "%(asctime)s" if self.no_colors else colored("%(asctime)s", "magenta")
        level = "%(levelname)s" if self.no_colors else self.FORMATS.get(record.levelno)

        fmt = f"{time}-[{level}][%(name)s]: {record.msg}"
        formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d,%H:%M:%S")

        try:
            return formatter.format(record)

        except:
            record.message = record.getMessage()
            if self.usesTime():
                record.asctime = self.formatTime(record, self.datefmt)

            s = self.formatMessage(record)

            if record.exc_info:
                # Cache the traceback text to avoid converting it multiple times
                # (it's constant anyway)
                if not record.exc_text:
                    record.exc_text = self.formatException(record.exc_info)

            if record.exc_text:
                if s[-1:] != "\n":
                    s = s + "\n"
                s = s + record.exc_text

            if record.stack_info:
                if s[-1:] != "\n":
                    s = s + "\n"
                s = s + self.formatStack(record.stack_info)

            return s


if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

file_name = "info.log"
file_path = os.path.join(LOGS_DIR, file_name)

stream_handler = logging.StreamHandler(stream=sys.stdout)
stream_handler.setFormatter(CustomFormatter())

rotating_handler = TimedRotatingFileHandler(file_path, when="midnight", backupCount=10)
rotating_handler.namer = lambda name: name.replace(".log", "") + ".log"
rotating_handler.setFormatter(CustomFormatter(no_colors=True))

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    handlers=[stream_handler, rotating_handler],
)

if DEBUG:
    for l in ["asyncio", "werkzeug"]:
        logging.getLogger(l).setLevel(logging.WARNING)
else:
    for l in ["socketio", "asyncio", "werkzeug"]: 
        logging.getLogger(l).setLevel(logging.WARNING)