import streamlit as st
import os
import base64 # Necesario para codificar las imágenes

st.set_page_config(page_title="Verificar Archivos", layout="wide")

# Obtenemos la ruta del directorio donde está este script (__file__)
current_dir = os.path.dirname(os.path.abspath(__file__))
# Subimos un nivel para llegar al directorio raíz del proyecto
PROJECT_ROOT = os.path.dirname(current_dir)


# --- PASO 2: USAR LA RUTA RAÍZ PARA CARGAR TODOS LOS ARCHIVOS ---

# Función para cargar y aplicar el CSS
def load_css(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as css_file:
            st.markdown(f"<style>{css_file.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.error(f"Error: No se pudo encontrar el archivo CSS en '{file_path}'.")

# Función para codificar imágenes (sin cambios)
@st.cache_data
def get_img_as_base64(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        return base64.b64encode(data).decode()
    except FileNotFoundError:
        # st.error(f"Error: No se pudo encontrar la imagen en '{file_path}'.")
        return None # Devuelve None si la imagen no se encuentra


# --- PASO 3: LLAMAR A LAS FUNCIONES CON LAS RUTAS CORRECTAS ---

# Construir la ruta completa al archivo CSS
css_path = os.path.join(PROJECT_ROOT, "styles.css")
load_css(css_path)

# Construir las rutas completas a las imágenes
logo_izq_path = os.path.join(PROJECT_ROOT, "images", "inv_teclogo.png")
logo_der_path = os.path.join(PROJECT_ROOT, "images", "inv_prepanet.png")

img_logo_izq = get_img_as_base64(logo_izq_path)
img_logo_der = get_img_as_base64(logo_der_path)


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

st.session_state.current_page = "Verificar Firma"

if st.session_state.current_page == "Verificar Firma":
    st.markdown("---")  # Separador visual
    st.subheader("No es necesario crear una cuenta para verificar archivos.")
    render_verificar_firma_page()

# --- PIE DE PÁGINA (al final del script) ---
# ###############################################################

if img_logo_izq and img_logo_der:
    footer_html = f"""
    <div class="footer">
        <img src="data:image/png;base64,{img_logo_izq}" class="footer-logo">
        <div class="footer-text">
            TInstituto Tecnológico y de Estudios Superiores de Monterrey CEM <br>
            Carretera Lago de Guadalupe 35, 52924 Ciudad López Mateos, MEX · 10 km <br>
            Tel: (81) 8358 2000
        </div>
        <img src="data:image/png;base64,{img_logo_der}" class="footer-logo">
    </div>
    """
    st.markdown(footer_html, unsafe_allow_html=True)


