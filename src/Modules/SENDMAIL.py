from email.message import EmailMessage
from dotenv import load_dotenv
import os, smtplib
import logging

log = logging.getLogger("SENDMAIL")
load_dotenv("config.env")

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSW = os.getenv("EMAIL_PASSW")

def SEND_MAIL(To="",Subject="",Message="",Subtype="html"):
    try:
        try:
            smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
            smtpObj.ehlo()
            smtpObj.starttls()
        except Exception as e_starttls:
            log.error(f"[{EMAIL_USER}] [Error STARTTLS Gmail] {e_starttls}")
            smtpObj = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        except Exception as e_conexion:
            log.error(f"[{EMAIL_USER}] [Error CONEXION SMTP Gmail] {e_conexion}")
            return False

        email = EmailMessage()
        email["From"] = EMAIL_USER
        email["To"] = To
        email["Subject"] = Subject
        email.set_content(Message, subtype=Subtype)
        email.set_charset('utf-8')

        smtpObj.login(EMAIL_USER, EMAIL_PASSW)
        smtpObj.sendmail(EMAIL_USER, To, email.as_string())
        smtpObj.quit()
        return True
    except smtplib.SMTPAuthenticationError as e_auth:
        log.error(f"[{EMAIL_USER}] [Error AUTENTICACION Gmail] {e_auth}")
        print(f"Error de autenticación SMTP (Gmail): {e_auth}. Revisa tu usuario y contraseña de Gmail en .env.")
        return False
    except Exception as e:
        log.error(f"[{EMAIL_USER}] [Error GENERAL Gmail] {e}")
        print(f"Error al enviar el correo con Gmail: {e}")
        return False

if __name__ == "__main__":
    print(f"CLIENTE PARA ENVIAR CORREOS DESDE GMAIL {EMAIL_USER}")
    PARA = input("ESCRIBE LA DIRECCION DE CORREO A LA QUE VA A ENVIAR: ")
    ASUNTO = input("ESCRIBE EL ASUNTO DEL CORREO: ")
    MENSAGE = input("ESCRIBE EL MENSAJE DEL CORREO: ")
    if SEND_MAIL(PARA, ASUNTO, MENSAGE):
        print("Correo enviado correctamente (Gmail).")
    else:
        print("Fallo al enviar el correo (Gmail). Revisa los errores impresos anteriormente.")