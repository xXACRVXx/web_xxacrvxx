# xXACRVXx Web: Mi Plataforma Web Personal Open-Source

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![GitHub Repo](https://img.shields.io/badge/GitHub-Repository-blue?logo=github)](https://github.com/xXACRVXx/web_xxacrvxx)

## Descripción del Proyecto

`xXACRVXx Web` es mi plataforma web personal open-source, desarrollada utilizando Python y Flask.  Ofrece un conjunto de herramientas y funcionalidades diseñadas para la gestión de archivos personales en la nube, la creación de un blog y la interacción a través de comentarios, todo en una misma aplicación web.

Esta plataforma proporciona una solución integral y **versátil**, adaptable tanto a entornos de **internet pública** como a **redes locales (intranet)**, para usuarios que buscan:

*   **Almacenamiento y Gestión de Archivos Personales:**  Permite subir, organizar y acceder a mis archivos desde cualquier dispositivo con conexión de red. Ideal para crear una nube personal accesible desde cualquier ubicación, ya sea en internet o dentro de una red local.
*   **Creación de un Blog Personal o Comunitario:** Facilita la publicación de contenido, desde notas personales hasta artículos más elaborados, con soporte para categorías, etiquetas y un sistema de comentarios para fomentar la interacción y la creación de comunidad.
*   **Un Espacio Web Personalizable y Controlado:**  `xXACRVXx Web` es un proyecto open-source, lo que te da la libertad de adaptarlo, extenderlo y desplegarlo en el entorno de red que mejor se ajuste a tus necesidades, manteniendo el control total sobre mis datos.

## Características Principales

*   **Autenticación de Usuarios:**  Sistema completo de gestión de usuarios con registro, inicio de sesión seguro, cierre de sesión, recuperación de contraseña y confirmación de correo electrónico.
*   **Blog Multifuncional:**  Crea y gestiona un blog con soporte para publicaciones formateadas en Markdown, categorías y etiquetas para organizar el contenido, y un sistema de comentarios para interactuar con los lectores.
*   **Gestor de Archivos Integrado:**  Sube, descarga, organiza y elimina archivos de forma intuitiva a través de la interfaz web, accesible tanto en internet como en redes locales.
*   **Interfaz de Usuario Moderna y Adaptable:**  Diseño responsivo que se adapta a diferentes tamaños de pantalla (ordenadores, tablets, móviles) y modo oscuro para una experiencia visual confortable en cualquier entorno.
*   **Flexibilidad de Despliegue:**  Funciona tanto en **internet pública** como en **redes locales (intranet)**, ofreciendo versatilidad en su uso.
*   **Servicio de Correo Electrónico Personalizable:**  Configurado por defecto para usar Outlook, pero fácilmente adaptable para utilizar **cualquier servidor SMTP**, permitiendo su uso en redes locales con servidores de correo internos.
*   **APIs Experimentales:**  Incluye APIs para funcionalidades de autenticación e integración con bots, pensadas para futuras extensiones y personalizaciones avanzadas.

## Pila Tecnológica

*   Python, Flask, PostgreSQL, HTML, CSS, JavaScript, Jinja2 y otras bibliotecas listadas en [requirements.txt](requirements.txt).

## Configuración e Instalación

Para ejecutar `xXACRVXx Web` localmente o en un entorno de servidor, sigue estas instrucciones:

**Requisitos Previos:**

*   Python 3.8 o superior (recomendado 3.11)
*   PostgreSQL instalado y en ejecución
*   Docker (opcional, para despliegue con Docker Compose)

**Instalación Manual (Sin Docker):**

1.  **Clonar el Repositorio:**
    ```bash
    git clone https://github.com/xXACRVXx/web_xxacrvxx.git
    cd web_xxacrvxx/src
    ```

2.  **Crear un Entorno Virtual (Recomendado):**
    ```bash
    python3 -m venv .venv
    # En Linux/macOS
    source .venv/bin/activate
    # En Windows
    .venv\Scripts\activate
    ```

3.  **Instalar Dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configurar las Variables de Entorno:**

    *   Crea un archivo llamado `config.env` en el directorio `src`.
    *   Añade las siguientes variables de entorno en este archivo:

        **Variables de Entorno:**

        *   `DEBUG`:  Activa o desactiva el modo debug para el logging.  Valores: `True` (activado) o `False` (desactivado).  Recomendado `False` para producción y `True` para desarrollo.
        *   `EMAIL_WEBMASTER`:  Dirección de correo electrónico del webmaster. Utilizada para recibir notificaciones y mensajes de contacto desde la web.
        *   `SECRET_KEY`:  Clave secreta utilizada por Flask para la seguridad de la aplicación, el cifrado de la base de datos y la generación de tokens JWT.  **Debe ser una cadena aleatoria y segura.**
        *   `EMAIL_USER` y `EMAIL_PASSW`: (Opcional)  Credenciales de una cuenta de correo electrónico de Outlook.  Requeridas solo si deseas habilitar las funcionalidades de envío de correo electrónico (ej., confirmación de registro, recuperación de contraseña).
        *   `HOST_DB`, `PORT_DB`, `NAME_DB`, `USERPG_DB`, `PASSWPG_DB`:  Parámetros de conexión a la base de datos PostgreSQL. Debes configurar estos valores para que coincidan con tu instalación de PostgreSQL.

        **Ejemplo de `config.env`:**
        ```env
        DEBUG=False
        ##################################

        #Webmaster email for send notifications
        EMAIL_WEBMASTER =tu_email@example.com
        ##################################

        #Secret key for flask app, db encript and jwt token
        SECRET_KEY =TuClaveSecretaAqui
        ###################################################

        #Outlook login (para envío de correos, opcional)
        EMAIL_USER =tu_email_outlook@outlook.com
        EMAIL_PASSW =TuContraseñaOutlook
        ##############

        #PostgreSQL Database
        HOST_DB = localhost
        PORT_DB = 5432
        NAME_DB = nombre_de_tu_base_de_datos
        USERPG_DB = usuario_postgres
        PASSWPG_DB = contraseña_postgres
        ####################
        ```
        **Nota:** Ajusta los valores de conexión a tu base de datos PostgreSQL y configura las credenciales de correo electrónico si planeas utilizar las funcionalidades de envío de correo.

    *   **Servidor SMTP Personalizado (Redes Locales/Intranet):**  Si planeas desplegar `xXACRVXx Web` en una red local o intranet **sin acceso a internet**, o si prefieres utilizar un servidor SMTP diferente a Outlook, puedes personalizar la configuración de envío de correo electrónico.  Para ello, modifica el archivo `Modules/SENDMAIL.py` y ajusta la configuración del servidor SMTP (`server = smtplib.SMTP('smtp.example.com', 587)`) para que coincida con tu servidor de correo interno.

5.  **Ejecutar la Aplicación Flask:**
    ```bash
    python app.py
    ```

    La aplicación se iniciará y estará disponible en `http://127.0.0.1:9001/` (o la dirección que indique la consola).

**Instalación con Docker Compose (Opcional - Para Escalabilidad):**

1.  **Asegúrate de tener Docker y Docker Compose instalados.**

2.  **Clonar el Repositorio:**
    ```bash
    git clone https://github.com/xXACRVXx/web_xxacrvxx.git
    cd web_xxacrvxx/
    ```

3.  **Configurar las Variables de Entorno:**
    *   Crea un archivo llamado `config.env` en el directorio `src` y configura las variables de entorno necesarias (ver ejemplo en la sección de Instalación Manual).

4.  **Construir e Iniciar con Docker Compose:**
    ```bash
    docker-compose up --build
    ```

    Docker Compose utilizará el `Dockerfile` proporcionado en el repositorio para construir la imagen de la aplicación y luego iniciar los servicios definidos en `compose.yaml`. La aplicación estará accesible en los puertos configurados en `compose.yaml`.

    **Contenido de `Dockerfile` (para referencia):**
    ```dockerfile
    FROM python:3.12.5-slim

    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    WORKDIR /src

    CMD [ "python3", "app.py" ]
    ```

    **Contenido de `compose.yaml` (para referencia):**
    ```yaml
    services:
      web:
        build:
          context: .
        restart: always
        deploy:
          replicas: 3
        ports:
          - "9001-9003:9001"
        volumes:
          - "./src:/src"
        env_file: src/config.env
    ```

## Uso

`xXACRVXx Web` ofrece una interfaz web intuitiva para gestionar tus archivos personales, publicar contenido en un blog y participar en la sección de comentarios.  Su **flexibilidad** permite utilizarla tanto en **entornos personales** como en **redes corporativas o educativas**.

## Contribuciones

Contribuciones bienvenidas.

## Contacto

[xxacrvxx@duck.com](mailto:xxacrvxx@duck.com) | Telegram: [@xXACRVXx](https://t.me/xXACRVXx)

## Licencia

[Licencia MIT](https://opensource.org/licenses/MIT)