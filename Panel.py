# Panel.py
import streamlit as st
import base64 # Necesario para codificar las imágenes
import os
import boto3

# Accede a las variables desde los secrets de Streamlit
aws_access_key_id = st.secrets["AWS_ACCESS_KEY_ID"]
aws_secret_access_key = st.secrets["AWS_SECRET_ACCESS_KEY"]
region_name = st.secrets["S3_AUTH_REGION"]
bucket_name = st.secrets["S3_AUTH_BUCKET_NAME"]
users_file = st.secrets["S3_AUTH_USERS_FILE"]

# Usa las variables para crear el cliente de S3
s3_client = boto3.client(
    's3',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=region_name
)

# Ahora puedes usar s3_client para interactuar con tu bucket
# por ejemplo, para leer el archivo de usuarios:
try:
    response = s3_client.get_object(Bucket=bucket_name, Key=users_file)
    user_data = response['Body'].read().decode('utf-8')
    # ... procesar user_data
except Exception as e:
    st.error(f"No se pudo acceder al archivo de configuración en S3: {e}")


# IMPORTANTE PARA EL CSS
st.set_page_config(page_title="Plataforma de Firma Digital", layout="wide")

# --- FUNCIÓN PARA CODIFICAR IMÁGENES ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Esto es mejor que rutas directas para que funcione bien al desplegar la app
@st.cache_data
def get_img_as_base64(file):
    with open(file, "rb") as f:
        data = f.read()
    return base64.b64encode(data).decode()

# --- Carga de imágenes con ruta robusta y nombres correctos ---
try:
    # 1. Nombres completos y correctos de tus archivos
    logo_izq_filename = "inv_teclogo.png"
    logo_der_filename = "inv_prepanet.png"

    # 2. Construimos la ruta absoluta y a prueba de errores
    img_logo_izq_path = os.path.join(BASE_DIR, "images", logo_izq_filename)
    img_logo_der_path = os.path.join(BASE_DIR, "images", logo_der_filename)

    img_logo_izq = get_img_as_base64(img_logo_izq_path)
    img_logo_der = get_img_as_base64(img_logo_der_path)

except FileNotFoundError:
    st.error("ERROR: No se pudo encontrar uno o ambos logos. Verifica que la carpeta 'images' esté al mismo nivel que 'Panel.py' y que los nombres de los archivos sean correctos.")
    img_logo_izq = img_logo_der = ""

################################
try:
    css_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "styles.css")
    if not os.path.exists(css_path):
        st.error(f"Error: El archivo CSS no se encuentra en la ruta esperada: {css_path}")
    else:
        with open(css_path, "r", encoding="utf-8") as css_file:
            css_content = css_file.read()
        st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)
except Exception as e:
    st.error(f"Error inesperado al cargar el archivo CSS: {e}")

# --- Importar funciones de autenticación y S3 ---
try:
    from auth_utils import (
        # Funciones de autenticación de usuario
        load_users_from_s3, save_users_to_s3, verify_password,
        hash_password, generate_salt, initialization_error,
        # Funciones de gestión de claves en S3 (si las usas directamente aquí o en app_content)
        save_public_key_to_s3, load_public_key_from_s3
        # save_encrypted_private_key_to_s3, load_and_decrypt_private_key_from_s3 # Si las implementas
    )
except ImportError:
    st.error("Error crítico: No se pudo importar 'auth_utils.py'. "
             "Asegúrate de que el archivo exista en el directorio principal.")
    st.stop()

# --- Importar funciones de renderizado de páginas de la aplicación ---
try:
    from app_content import (
        render_pagina_principal_logueado,
        render_genere_su_firma_page,
        render_firme_documentos_page,
        render_verificar_firma_page
    )
except ImportError:
    st.error("Error crítico: No se pudo importar 'app_content.py'. "
             "Asegúrate de que el archivo exista y contenga las funciones de renderizado de página.")
    st.stop()

# --- Inicializar estado de sesión de Streamlit ---


# Necesario para mantener el estado entre interacciones/recargas de la página.
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'current_page' not in st.session_state:
    # Página por defecto al iniciar o después de cerrar sesión
    st.session_state.current_page = "Iniciar Sesión"  # O "Verificar Firma" si quieres que sea el default público

# Inicializar estados específicos de las sub-páginas si es necesario globalmente
# (Aunque es mejor inicializarlos dentro de sus respectivas funciones render_ si solo se usan allí)
if 'generated_keys_data' not in st.session_state:  # Usado en render_genere_su_firma_page
    st.session_state.generated_keys_data = None
if 'signature_details' not in st.session_state:  # Usado en render_firme_documentos_page
    st.session_state.signature_details = None


# --- Funciones para el Formulario de Login y Signup ---
def display_login_form():
    st.subheader("Iniciar Sesión")

    if initialization_error:  # Chequea error de auth_utils.py
        st.error(f"Error de configuración del sistema: {initialization_error}")
        st.warning("El inicio de sesión no está disponible actualmente.")
        return

    # Usar columnas para centrar un poco el formulario
    # col1, col_form, col3 = st.columns([1, 1.5, 1]) # Ajusta proporciones
    # with col_form:
    with st.form("login_form"):
        username = st.text_input("Nombre de Usuario:", key="main_login_user")
        password = st.text_input("Contraseña:", type="password", key="main_login_pass")
        submit_button = st.form_submit_button("Acceder")

        if submit_button:
            if not username or not password:
                st.error("Por favor, ingrese su nombre de usuario y contraseña.")
            else:
                users = load_users_from_s3()
                if username in users:
                    user_data = users[username]
                    if verify_password(user_data['hash'], user_data['salt'], password):
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.current_page = "Página Principal"  # Redirigir después de login
                        st.success("¡Inicio de sesión exitoso!")
                        st.rerun()  # Recargar la app para reflejar el estado de login
                    else:
                        st.error("Contraseña incorrecta.")
                else:
                    st.error("Nombre de usuario no encontrado.")


def display_signup_form():
    st.subheader("Crear Nueva Cuenta")

    if initialization_error:  # Chequea error de auth_utils.py
        st.error(f"Error de configuración del sistema: {initialization_error}")
        st.warning("La creación de cuentas no está disponible actualmente.")
        return

    # col1, col_form, col3 = st.columns([1, 1.5, 1])
    # with col_form:
    with st.form("signup_form"):
        new_username = st.text_input("Cree su Nombre de Usuario:", key="main_signup_user")
        new_password = st.text_input("Ingrese su Contraseña:", type="password", key="main_signup_pass1")
        confirm_password = st.text_input("Verifique su Contraseña:", type="password", key="main_signup_pass2")
        aceptar = st.checkbox("Estoy de acuerdo con el Aviso de privacidad")
        submit_button = st.form_submit_button("Crear Cuenta")

        if submit_button:
            if not all([new_username, new_password, confirm_password, aceptar]):
                st.error("Todos los campos son obligatorios.")
            elif aceptar == False:
                st.error("Acepte el aviso de privacidad")
            elif new_password != confirm_password:
                st.error("Las contraseñas no coinciden.")
            elif len(new_password) < 8:  # Ejemplo de validación de contraseña
                st.error("La contraseña debe tener al menos 8 caracteres.")
            else:
                users = load_users_from_s3()
                if new_username in users:
                    st.error("Este nombre de usuario ya existe. Por favor, elija otro.")
                else:
                    salt = generate_salt()
                    hashed_pw = hash_password(new_password, salt)
                    users[new_username] = {"hash": hashed_pw, "salt": salt}
                    if save_users_to_s3(users):
                        st.success(f"¡Cuenta para '{new_username}' creada exitosamente! Ahora puede iniciar sesión.")
                        # Podrías limpiar los campos o cambiar a la pestaña de login aquí
                    else:
                        st.error("Error al guardar la nueva cuenta. "
                                 "Intente de nuevo o contacte al administrador si el problema persiste.")
    # URL del PDF
    # Mostrar el enlace justo al lado del checkbox
    # Mostrar el checkbox con el texto y el enlace
    pdf_url = "https://bucket-weezing-bp.s3.us-east-2.amazonaws.com/media/TERMINOS-Y-CONDICIONES-GENERALES.pdf"
    st.markdown(f"[Ver Aviso de privacidad]({pdf_url})")


# --- Lógica Principal de la Aplicación Streamlit ---
#st.set_page_config(page_title="Plataforma de Firma Digital", layout="wide")

# Mostrar error global de inicialización de S3 si existe (de auth_utils.py)
if initialization_error:
    st.error(
        f"⚠️ Error Crítico de Configuración: {initialization_error}. Algunas funcionalidades pueden no estar disponibles. Contacte al administrador.")

# --- Renderizado condicional basado en el estado de login ---
if not st.session_state.logged_in:
    st.title("Bienvenido a la Plataforma de Firma Digital")
    st.markdown("Por favor, inicie sesión para acceder a todas las funcionalidades o cree una cuenta nueva.")

    # Permitir acceso a la verificación de firmas sin estar logueado
    col_nav1, col_nav2, col_nav3 = st.columns([1, 3, 1])
    with col_nav2:
        login_tab_title = "Iniciar Sesión"
        signup_tab_title = "Crear Cuenta"
        # Verificar si se debe enfocar alguna pestaña
        # (ej. si st.session_state.current_page fue seteado a 'Iniciar Sesión' o 'Crear Cuenta')

        tab_login, tab_signup = st.tabs([login_tab_title, signup_tab_title])
        with tab_login:
            display_login_form()
        with tab_signup:
            display_signup_form()

else:
    # --- Usuario Logueado: Mostrar Barra Lateral de Navegación y Contenido de la Página ---
    with st.sidebar:
        st.title(f"Hola, {st.session_state.username}!")
        st.markdown("---")

        # Definir las opciones del menú para el usuario logueado
        opciones_menu_logueado = {
            "Página Principal": "🏠 Página Principal",
            "Genere su firma": "🔑 Genere su Firma",
            "Firme documentos": "✍️ Firme Documentos",
            "Verificar Firma": "🔎 Verificar Firma"
        }

        # Usar st.session_state.current_page para recordar la selección
        # y asegurar que el índice sea válido.
        lista_opciones = list(opciones_menu_logueado.keys())

        try:
            current_index = lista_opciones.index(st.session_state.current_page)
        except ValueError:  # Si current_page no está en la lista (ej. después de login)
            current_index = 0  # Default a la primera opción
            st.session_state.current_page = lista_opciones[current_index]

        seleccion = st.radio(
            "Menú de Aplicación:",
            lista_opciones,
            format_func=lambda x: opciones_menu_logueado[x],  # Mostrar etiquetas amigables
            index=current_index,
            key="sidebar_nav_radio"
        )

        if seleccion != st.session_state.current_page:
            st.session_state.current_page = seleccion
            # Limpiar estados de página anteriores si es necesario
            st.session_state.generated_keys_data = None
            st.session_state.signature_details = None
            st.rerun()

        st.markdown("---")
        if st.button("Cerrar Sesión", key="sidebar_logout_button"):
            # Limpiar el estado de sesión relacionado con el usuario
            st.session_state.clear()
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.current_page = "Iniciar Sesión"  # O default público
            st.session_state.generated_keys_data = None
            st.session_state.signature_details = None
            # st.success("Sesión cerrada exitosamente.") # Se mostrará en la página de login
            st.rerun()

    # --- Renderizar el contenido de la página seleccionada por el usuario logueado ---
    if st.session_state.current_page == "Página Principal":
        render_pagina_principal_logueado()
    elif st.session_state.current_page == "Genere su firma":
        render_genere_su_firma_page()
    elif st.session_state.current_page == "Firme documentos":
        render_firme_documentos_page()
    elif st.session_state.current_page == "Verificar Firma":
        render_verificar_firma_page()
    else:  # Por si acaso current_page tiene un valor inesperado
        st.warning(f"Página '{st.session_state.current_page}' no reconocida. Mostrando Página Principal.")
        render_pagina_principal_logueado()

######################
# --- PIE DE PÁGINA (al final de tu script) ---
# Importante: Ajustamos el tipo de imagen a "image/jpeg"
if img_logo_izq and img_logo_der:
    footer_html = f"""
    <div class="footer">
        <img src="data:image/jpeg;base64,{img_logo_izq}" class="footer-logo">
        <div class="footer-text">
            Instituto Tecnológico y de Estudios Superiores de Monterrey CEM <br>
            Carretera Lago de Guadalupe 35, 52924 Ciudad López Mateos, MEX · 10 km <br>
            Tel: (81) 8358 2000
        </div>
        <img src="data:image/jpeg;base64,{img_logo_der}" class="footer-logo">
    </div>
    """
    st.markdown(footer_html, unsafe_allow_html=True)