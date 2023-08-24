from email.message import EmailMessage
from dotenv import load_dotenv
import os, smtplib
import logging
# smtp outlook

load_dotenv("config.env") # carga las variables de entorno desde el archivo .env

log = logging.getLogger("SENDMAIL")


EMAIL_USER = os.getenv("EMAIL_USER")

EMAIL_PASSW = os.getenv("EMAIL_PASSW")



def SEND_MAIL(To="",Subject="",Message="",Subtype="html"):
    try:

        try:
            smtpObj = smtplib.SMTP('smtp-mail.Outlook.com', 587)
        except Exception as e:
            smtpObj = smtplib.SMTP_SSL('smtp-mail.Outlook.com', 465)
            
        email = EmailMessage()
        email["From"] = EMAIL_USER
        email["To"] = To
        email["Subject"] = Subject
        email.set_content(Message, subtype=Subtype)
        email.set_charset('utf-8') # añadido para evitar problemas de codificación

        # type(smtpObj)
        smtpObj.ehlo()
        smtpObj.starttls()
        smtpObj.login(EMAIL_USER, EMAIL_PASSW)
        smtpObj.sendmail(EMAIL_USER, To, email.as_string())   # Or recipient@Outlook
        smtpObj.quit()
        return True
    except Exception as e:
        log.error(f"[{EMAIL_USER}] [Error] {e}")
        return False

if __name__ == "__main__":
    print(f"CLIENTE PARA ENVIAR CORREOS DESDE {EMAIL_USER}")
    PARA = input("ESCRIBE LA DIRECCION DE CORREO A LA QUE VA A ENVIAR: ")
    ASUNTO = input("ESCRIBE EL ASUNTO DEL CORREO: ")
    MENSAGE = input("ESCRIBE EL MENSAJE DEL CORREO: ")
    SEND_MAIL(PARA, ASUNTO, MENSAGE)
    print("correo enviado")
