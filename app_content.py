# app_content.py

import streamlit as st
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

s3_client = boto3.client('s3', region_name='us-west-2')

# Importaciones de cryptography
from cryptography.hazmat.primitives.asymmetric import  padding as rsa_padding  # Renombrar padding para evitar conflicto si usas otro
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions  # Para InvalidSignature
from auth_utils import *
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from streamlit_extras.let_it_rain import rain

# Importar funciones de S3 desde auth_utils si son necesarias DENTRO de estas funciones de renderizado
# (ej. si se llama a save_public_key_to_s3 directamente desde render_genere_su_firma_page)
try:
    from auth_utils import save_public_key_to_s3, load_public_key_from_s3
    # from auth_utils import load_and_decrypt_private_key_from_s3 # Si implementas carga de clave privada S3
except ImportError:
    # Esto es más para desarrollo, en producción auth_utils debería estar.
    # Podrías definir funciones mock aquí si quieres probar app_content.py aisladamente.
    st.warning(
        "ADVERTENCIA (app_content): No se pudo importar auth_utils.py. Las funciones de S3 no estarán disponibles.")


    def save_public_key_to_s3(username, bytes_data):
        return False


    def load_public_key_from_s3(username):
        return None
    # def load_and_decrypt_private_key_from_s3(username, password): return None


# --- Funciones de Utilidad ---
# (Función obtener_hash_documento_bytes debería estar definida o importada)
def obtener_hash_documento_bytes(documento_bytes):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(documento_bytes)
    hash_final = digest.finalize()
    return hash_final


# --- Funciones de Renderizado de Páginas ---

def render_pagina_principal_logueado():
    """Muestra la página principal para usuarios logueados."""
    st.title(f"🏠 Bienvenido a su Panel, {st.session_state.get('username', 'Usuario')}!")
    st.markdown("""
    Esta es su plataforma de confianza para la gestión de firmas digitales.
    Utilice el menú de la izquierda para navegar por las diferentes funcionalidades:

    - **Genere su Firma:** Cree un nuevo par de claves (pública y privada) para firmar digitalmente.
    - **Firme Documentos:** Utilice su clave privada para aplicar una firma digital a sus documentos.
    - **Verificar Firma:** Compruebe la autenticidad e integridad de un documento firmado digitalmente.

    ¡Su seguridad y la integridad de sus documentos son nuestra prioridad!
    """)
    st.info("Recuerde mantener su clave privada segura y no compartirla con nadie.")


def render_genere_su_firma_page():
    st.title("🔑 Genere su Firma Digital")
    st.markdown("""
    Aquí puede generar un nuevo par de claves criptográficas (pública y privada).
    Puede elegir entre el algoritmo **RSA** (2048 bits, ampliamente compatible) o **ECDSA** (curva P-256, eficiente y moderna).

    - **Clave Privada:** Deberá descargarla y guardarla en un lugar extremadamente seguro. Es secreta y se utiliza para crear firmas digitales.
    - **Clave Pública:** Puede descargarla y compartirla. Se utiliza para que otros puedan verificar sus firmas. También tiene la opción de guardarla en su cuenta para facilitar su uso en esta plataforma.
    """)
    st.markdown("---")

    # Usar st.session_state para almacenar las claves generadas
    if 'generated_keys_info' not in st.session_state:  # Cambiado de generated_keys_data
        st.session_state.generated_keys_info = None

    st.subheader("""**Consideraciones de Seguridad:** """)
    st.markdown(""" 
    - La Clave Privada es su identidad digital secreta. Si alguien más la obtiene, puede firmar documentos en su nombre. Guárdela de forma segura y considere encriptar el archivo descargado en su sistema local.
    - Esta aplicación genera claves privadas sin protección por contraseña adicional en el archivo PEM descargado.
    - Recomendamos hacer este paso UNA SOLA VEZ. """)

    st.subheader("Seleccione el Tipo de Clave a Generar:")
    col_rsa, col_ecdsa = st.columns(2)

    with col_rsa:
        if st.button("🔑 Generar Par de Claves RSA", key="gen_rsa_keys_btn_page", type="secondary"):
            with st.spinner("Generando claves RSA... Por favor espere."):
                private_key_rsa_obj = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                public_key_rsa_obj = private_key_rsa_obj.public_key()
                pem_priv_rsa = private_key_rsa_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                pem_pub_rsa = public_key_rsa_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                st.session_state.generated_keys_info = {
                    "type": "RSA",
                    "private_key_obj": private_key_rsa_obj,
                    "public_key_obj": public_key_rsa_obj,
                    "pem_private": pem_priv_rsa,
                    "pem_public": pem_pub_rsa,
                    "details_for_display": {
                        "Algoritmo": "RSA",
                        "Tamaño de Clave (bits)": "2048",
                        "Exponente Público (e)": str(public_key_rsa_obj.public_numbers().e),
                        # Mostrar n y d podría ser muy largo, opcional
                        # "Módulo (n)": str(public_key_rsa_obj.public_numbers().n),
                        # "Exponente Privado (d)": str(private_key_rsa_obj.private_numbers().d)
                    }
                }
            st.success("¡Par de claves RSA (2048 bits) generado exitosamente!")

    with col_ecdsa:
        if st.button("🔑 Generar Par de Claves ECDSA", key="gen_ecdsa_keys_btn_page", type="secondary"):
            with st.spinner("Generando claves ECDSA... Por favor espere."):
                private_key_ecdsa_obj = ec.generate_private_key(
                    curve=ec.SECP256R1(),  # Curva P-256, comúnmente usada
                    backend=default_backend()
                )
                public_key_ecdsa_obj = private_key_ecdsa_obj.public_key()
                pem_priv_ecdsa = private_key_ecdsa_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                pem_pub_ecdsa = public_key_ecdsa_obj.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                st.session_state.generated_keys_info = {
                    "type": "ECDSA",
                    "private_key_obj": private_key_ecdsa_obj,
                    "public_key_obj": public_key_ecdsa_obj,
                    "pem_private": pem_priv_ecdsa,
                    "pem_public": pem_pub_ecdsa,
                    "details_for_display": {
                        "Algoritmo": "ECDSA",
                        "Curva": "SECP256R1 (P-256)",
                        # "Valor Privado (d)": str(private_key_ecdsa_obj.private_numbers().private_value),
                        # "Punto Público (x)": str(public_key_ecdsa_obj.public_numbers().x),
                        # "Punto Público (y)": str(public_key_ecdsa_obj.public_numbers().y),
                    }
                }
            st.success("¡Par de claves ECDSA (P-256) generado exitosamente!")

    # Mostrar claves si han sido generadas en esta sesión
    if st.session_state.get("generated_keys_info"):
        info = st.session_state.generated_keys_info
        key_type = info["type"]
        pem_private_key = info["pem_private"]
        pem_public_key = info["pem_public"]

        st.markdown("---")
        st.subheader(f"Claves {key_type} Generadas:")

        col_priv_disp, col_pub_disp = st.columns(2)
        with col_priv_disp:
            st.markdown(f"##### Clave Privada {key_type} (Formato PEM)")
            st.text_area(
                f"Contenido Clave Privada {key_type}:",
                pem_private_key.decode(),
                height=250,
                key=f"priv_key_display_area_{key_type.lower()}",
                help="¡IMPORTANTE! Copie todo este texto, incluyendo las líneas -----BEGIN...----- y -----END...-----, y guárdelo en un archivo (ej. private_key.pem). ¡Manténgala secreta y segura!"
            )
            st.download_button(
                label=f"📥 Descargar Clave Privada {key_type}",
                data=pem_private_key,
                file_name=f"clave_privada_{key_type.lower()}_{st.session_state.get('username', 'usuario')}.pem",
                mime="application/x-pem-file",  # Para que se trate como archivo PEM
                key=f"download_priv_key_btn_action_{key_type.lower()}"
            )

        with col_pub_disp:
            st.markdown(f"##### Clave Pública {key_type} (Formato PEM)")
            st.text_area(
                f"Contenido Clave Pública {key_type}:",
                pem_public_key.decode(),
                height=250,
                key=f"pub_key_display_area_{key_type.lower()}",
                help="Puede compartir esta clave pública o el archivo descargado con quienes necesiten verificar sus firmas."
            )
            st.download_button(
                label=f"📥 Descargar Clave Pública {key_type}",
                data=pem_public_key,
                file_name=f"clave_publica_{key_type.lower()}_{st.session_state.get('username', 'usuario')}.pem",
                mime="application/x-pem-file",
                key=f"download_pub_key_btn_action_{key_type.lower()}"
            )

        st.markdown("---")
        st.subheader("Opciones Adicionales para su Clave Pública")
        if st.session_state.get("logged_in") and st.session_state.get("username"):
            # from auth_utils import save_public_key_to_s3 # Asegúrate de que esté importada
            if st.button(f"💾 Guardar mi Clave Pública {key_type} en S3 (Cuenta)",
                         key=f"save_s3_pub_key_btn_action_{key_type.lower()}"):
                # La función save_public_key_to_s3 ahora debería tomar key_type
                if save_public_key_to_s3(st.session_state.username, pem_public_key, key_type=key_type):
                    # El mensaje de éxito/error ya se maneja dentro de save_public_key_to_s3
                    pass
                else:
                    # El mensaje de error ya se maneja dentro de save_public_key_to_s3
                    pass
        else:
            st.info("Inicie sesión para tener la opción de guardar su clave pública en su cuenta de forma persistente.")

        with st.expander(f"Mostrar detalles técnicos de las claves {key_type} (Avanzado)"):
            details_to_show = info["details_for_display"]
            for detail_key, detail_value in details_to_show.items():
                st.text_input(
                    f"{detail_key}:",
                    str(detail_value),
                    disabled=True,
                    key=f"detail_val_display_{key_type.lower()}_{detail_key.replace(' ', '_').lower()}"
                )


def render_firme_documentos_page():
    """Renderiza la página para firmar documentos."""
    st.title("✍️ Firme sus Documentos Digitalmente")
    st.markdown("""
    Suba un documento y su clave privada (en formato PEM sin encriptar) para generar una firma digital.
    La firma prueba la autenticidad e integridad del documento.
    """)
    st.markdown("---")

    # Inicializar/limpiar estado específico de esta página si no existe
    if 'signature_details' not in st.session_state:  # Usado también en Panel.py para limpiar
        st.session_state.signature_details = None
    if 'firma_doc_bytes' not in st.session_state: st.session_state.firma_doc_bytes = None
    if 'firma_priv_key_bytes' not in st.session_state: st.session_state.firma_priv_key_bytes = None

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("1. Documento a Firmar")
        uploaded_document = st.file_uploader(
            "Seleccione el documento:",
            type=None,
            key="doc_uploader_firmar_page"  # Clave única para el widget
        )
        if uploaded_document:
            st.session_state.firma_doc_bytes = uploaded_document.read()
            st.session_state.firma_uploaded_doc_name = uploaded_document.name  # <--- GUARDAR NOMBRE
            st.caption(
                f"Archivo cargado: {uploaded_document.name} ({len(st.session_state.firma_doc_bytes) / 1024:.2f} KB)")

    with col2:
        st.subheader("2. Su Clave Privada")
        uploaded_private_key_file = st.file_uploader(
            "Suba su archivo de Clave Privada (.pem o .key):",
            type=['pem', 'key'],
            key="priv_key_uploader_firmar"
        )
        if uploaded_private_key_file:
            st.session_state.firma_priv_key_bytes = uploaded_private_key_file.getvalue()
            st.caption("Clave privada cargada desde archivo.")

        if not st.session_state.get("firma_priv_key_bytes"):  # Aún no hay clave
            private_key_pem_text = st.text_area(
                "O pegue el contenido de su Clave Privada (PEM):",
                height=150,
                key="priv_key_text_area_firmar",
                help="Si no sube un archivo, puede pegar el contenido PEM aquí."
            )
            if private_key_pem_text.strip():
                st.session_state.firma_priv_key_bytes = private_key_pem_text.strip().encode('utf-8')
                st.caption("Clave privada obtenida del área de texto.")

    st.markdown("---")
    if st.button("✒️ Generar Firma Digital del Documento", key="generate_signature_btn_firmar", type="primary",
                 use_container_width=True):
        if not st.session_state.get("firma_doc_bytes"):
            st.error("❌ Por favor, suba un documento para firmar.")
        elif not st.session_state.get("firma_priv_key_bytes"):
            st.error("❌ Por favor, suba o pegue su clave privada.")
        else:
            try:
                with st.spinner("Procesando y firmando..."):
                    # Cargar la clave privada desde los bytes PEM almacenados en session_state
                    private_key_pem_bytes = st.session_state.firma_priv_key_bytes
                    private_key = serialization.load_pem_private_key(
                        private_key_pem_bytes,
                        password=None,  # Asume que no está encriptada.
                        backend=default_backend()
                    )

                    # Hashear el documento
                    doc_hash_bytes = obtener_hash_documento_bytes(st.session_state.firma_doc_bytes)

                    signature_bytes = None
                    key_type_used = "Desconocido"  # Para informar al usuario

                    # Determinar el tipo de clave y firmar acordemente
                    if isinstance(private_key, rsa.RSAPrivateKey):
                        key_type_used = "RSA"
                        signature_bytes = private_key.sign(
                            doc_hash_bytes,
                            rsa_padding.PSS(  # Usar PSS padding para RSA
                                mgf=rsa_padding.MGF1(hashes.SHA256()),
                                salt_length=rsa_padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                        key_type_used = "ECDSA"
                        signature_bytes = private_key.sign(
                            doc_hash_bytes,  # ECDSA puede firmar el hash directamente
                            ec.ECDSA(hashes.SHA256())
                        )
                    else:
                        # Si la clave no es ni RSA ni ECDSA (o no se pudo cargar/identificar)
                        st.error(
                            "Tipo de clave privada no soportado o inválida. Solo se admiten claves RSA y ECDSA en formato PEM.")
                        # Limpiar detalles de firma si hubo un intento anterior
                        if 'signature_details' in st.session_state:
                            del st.session_state.signature_details
                        return  # Detener la ejecución aquí

                    # Guardar detalles de la firma en session_state para mostrar y descargar
                    # Obtener el nombre del documento si se subió
                    doc_name_for_sig = "documento_firmado"  # Default
                    # Necesitarías una forma de obtener el nombre del archivo si lo guardaste
                    # Por ejemplo, si guardaste el objeto UploadedFile:
                    # if 'firma_uploaded_doc_object' in st.session_state and st.session_state.firma_uploaded_doc_object:
                    #    doc_name_for_sig = st.session_state.firma_uploaded_doc_object.name
                    # Si no, tendrás que pensar cómo obtener el nombre original del archivo para la firma.
                    # Temporalmente, si solo tienes los bytes:
                    if hasattr(st.session_state, 'firma_uploaded_doc_name'):  # Si guardaste el nombre
                        doc_name_for_sig = st.session_state.firma_uploaded_doc_name

                    st.session_state.signature_details = {
                        "document_name": doc_name_for_sig,  # Usar el nombre del archivo original
                        "hash_hex": doc_hash_bytes.hex(),
                        "signature_hex": signature_bytes.hex(),
                        "signature_bytes": signature_bytes,
                        "key_type_used": key_type_used
                    }
                    st.success(f"¡Documento '{doc_name_for_sig}' firmado exitosamente con {key_type_used}!")

            except ValueError as ve:
                st.error(f"Error al cargar o procesar la clave privada: {ve}. "
                         "Asegúrese de que el formato PEM sea correcto y que la clave no esté protegida por contraseña.")
                if 'signature_details' in st.session_state: del st.session_state.signature_details
            except Exception as e:
                st.error(f"Ocurrió un error durante el proceso de firma: {e}")
                if 'signature_details' in st.session_state: del st.session_state.signature_details

    # Mostrar detalles de la firma si se generó
    if st.session_state.get("signature_details"):
        details = st.session_state.signature_details
        st.markdown("---")
        st.subheader("Detalles de la Firma Generada")
        st.write(f"**Documento:** {details['document_name']}")
        st.write("**Hash SHA-256 del Documento (hex):**")
        st.code(details['hash_hex'], language=None)
        st.write("**Firma Digital (hex):**")
        st.code(details['signature_hex'], language=None)
        st.download_button(
            label=f"📥 Descargar Firma ({details['document_name']}.sig)",
            data=details['signature_bytes'],
            file_name=f"{details['document_name']}.sig",
            mime="application/octet-stream",
            key="download_sig_btn"
        )


def list_all_users_with_keys():
    """
    Lista todos los nombres de usuario disponibles en el bucket de S3 a partir de la estructura:
    KEY_STORAGE_PATH_PREFIX/<username>/public_key_<TIPO>.pem
    Se utiliza el parámetro 'Delimiter' para obtener solo los directorios de nivel superior.
    """
    if initialization_error or not s3_client:
        st.error("Error de S3: No se pueden listar usuarios debido a un problema de inicialización del sistema.")
        return []
    try:
        response = s3_client.list_objects_v2(
            Bucket="bucket-weezing-bp",  # Usar la variable de entorno configurada
            Prefix=f"user_keys/",  # Usar el prefijo configurado
            Delimiter="/"
        )
        if "CommonPrefixes" in response:
            # Cada CommonPrefix tendrá un string del tipo "KEY_STORAGE_PATH_PREFIX/username/"
            users = [prefix.get("Prefix").split("/")[-2] for prefix in response["CommonPrefixes"]]
            return sorted(users)
        else:
            return []
    except Exception as e:
        st.error(f"Error al listar usuarios del bucket: {e}")
        return []


def render_verificar_firma_page():

    """Renderiza la página para verificar una firma digital (RSA o ECDSA)."""
    st.title("🔎 Verificar Firma Digital de un Documento")
    st.markdown("""
    Suba el documento original, el archivo de firma (.sig) y la clave pública del firmante
    (en formato PEM) para verificar la autenticidad e integridad del documento.
    La verificación intentará determinar si la firma es RSA o ECDSA basada en la clave pública proporcionada.
    """)
    st.markdown("---")

    # Usar variables de estado para mantener los datos subidos entre re-runs
    if 'original_doc_bytes_verify' not in st.session_state:
        st.session_state.original_doc_bytes_verify = None
    if 'signature_bytes_verify' not in st.session_state:
        st.session_state.signature_bytes_verify = None
    if 'public_key_pem_verify' not in st.session_state:
        st.session_state.public_key_pem_verify = None
    if 'selected_user_verify' not in st.session_state:
        st.session_state.selected_user_verify = None
    if 'key_type_to_load_s3_verify' not in st.session_state:
        st.session_state.key_type_to_load_s3_verify = "RSA"

    col1, col2, col3 = st.columns([1.5, 1.5, 2])  # Ajustar anchos de columna

    with col1:
        st.markdown("##### 1. Documento Original")
        uploaded_original_doc = st.file_uploader(
            "Suba el documento que fue firmado:",
            key="verify_original_doc_uploader_page",
            help="El archivo exacto que se firmó originalmente."
        )
        if uploaded_original_doc:
            st.session_state.original_doc_bytes_verify = uploaded_original_doc.read()
            st.caption(
                f"Cargado: {uploaded_original_doc.name} ({len(st.session_state.original_doc_bytes_verify) / 1024:.2f} KB)")

    with col2:
        st.markdown("##### 2. Archivo de Firma (.sig)")
        uploaded_signature_file = st.file_uploader(
            "Suba el archivo de firma digital:",
            type=['sig', 'signature'],
            key="verify_sig_file_uploader_page",
            help="El archivo .sig o .signature que contiene la firma."
        )
        if uploaded_signature_file:
            st.session_state.signature_bytes_verify = uploaded_signature_file.read()
            st.caption(
                f"Cargado: {uploaded_signature_file.name} ({len(st.session_state.signature_bytes_verify)} bytes)")

    with col3:
        st.markdown("##### 3. Clave Pública del Firmante (PEM)")

        st.write("**Búsqueda de usuario para cargar su clave pública desde S3**")

        # Selección del tipo de clave que se desea cargar
        st.session_state.key_type_to_load_s3_verify = st.selectbox(
            "Seleccione el tipo de clave pública a cargar de S3:",
            options=("RSA", "ECDSA"),
            index=0 if st.session_state.key_type_to_load_s3_verify == "RSA" else 1,
            key="s3_key_type_verify_select"
        )

        # Listar todos los usuarios disponibles en el bucket
        user_list = list_all_users_with_keys()
        if not user_list:
            st.warning("No se encontraron usuarios registrados en el bucket de S3.")
            st.session_state.selected_user_verify = None
        else:
            st.session_state.selected_user_verify = st.selectbox(
                "Seleccione un usuario:",
                user_list,
                index=user_list.index(
                    st.session_state.selected_user_verify) if st.session_state.selected_user_verify in user_list else 0,
                key="s3_user_select_verify"
            )

        # Botón para cargar automáticamente la clave pública seleccionada
        if st.session_state.selected_user_verify and st.button(
                f"Cargar clave pública para {st.session_state.selected_user_verify}",
                key="load_selected_s3_pubkey_verify_btn"
        ):
            loaded_pk_bytes = load_public_key_from_s3(st.session_state.selected_user_verify,
                                                      key_type=st.session_state.key_type_to_load_s3_verify)
            if loaded_pk_bytes:
                st.session_state.public_key_pem_verify = loaded_pk_bytes  # Actualizar el valor
                st.success(
                    f"Clave pública {st.session_state.key_type_to_load_s3_verify} cargada para el usuario {st.session_state.selected_user_verify} desde S3.")
            else:
                st.warning(
                    f"No se encontró la clave pública {st.session_state.key_type_to_load_s3_verify} para {st.session_state.selected_user_verify} o hubo un error al cargarla.")

        # Mostrar la clave cargada de S3 si se encuentra en session_state
        if st.session_state.public_key_pem_verify:
            try:
                st.text_area(
                    "Clave Pública cargada de S3 (PEM):",
                    st.session_state.public_key_pem_verify.decode(),
                    height=100,
                    disabled=True,
                    key="s3_pubkey_display_verify"
                )
            except UnicodeDecodeError:
                st.text_area(
                    "Clave Pública cargada de S3 (PEM):",
                    "[No se pudo decodificar la clave como texto, pero está cargada.]",
                    height=50,
                    disabled=True,
                    key="s3_pubkey_display_verify_error"
                )

        # Opción adicional: permitir subir manualmente la clave en caso de que no exista en S3 o se desee sobreescribir
        st.write("**Si lo desea, puede cargar el archivo .pem de una clave pública:**")
        uploaded_public_key_file = st.file_uploader(
            "Este apartado es opcional si ya cargó una clave desde S3.",
            type=['pem', 'pub'],
            key="verify_pub_key_file_uploader_page",
            help="El archivo .pem que contiene la clave pública del firmante."
        )
        if uploaded_public_key_file:
            st.session_state.public_key_pem_verify = uploaded_public_key_file.getvalue()  # Sobreescribir si se sube manualmente
            st.caption(f"Clave cargada desde archivo: {uploaded_public_key_file.name}")

    st.markdown("---")
    if st.button("🔍 Verificar Firma del Documento", key="verify_signature_btn_action_verify", type="primary",
                 use_container_width=True):
        # Verificar si todos los componentes necesarios están presentes
        missing_components = []
        if not st.session_state.original_doc_bytes_verify:
            missing_components.append("documento original")
        if not st.session_state.signature_bytes_verify:
            missing_components.append("archivo de firma")
        if not st.session_state.public_key_pem_verify:
            missing_components.append("clave pública")

        if missing_components:
            st.error(f"❌ Por favor, suba los siguientes componentes necesarios: {', '.join(missing_components)}.")
            rain(emoji="💥", font_size=80, falling_speed=2, animation_length=0.5)
        else:
            try:
                with st.spinner("Verificando firma... Por favor espere."):
                    # Cargar la clave pública desde los bytes almacenados
                    public_key_obj = serialization.load_pem_public_key(
                        st.session_state.public_key_pem_verify,
                        backend=default_backend()
                    )

                    # Calcular el hash del documento original subido
                    doc_hash_bytes_to_verify = obtener_hash_documento_bytes(st.session_state.original_doc_bytes_verify)

                    verification_successful = False
                    key_type_verified = "Desconocido"
                    error_detail = ""

                    # Intentar verificación RSA
                    if isinstance(public_key_obj, rsa.RSAPublicKey):
                        key_type_verified = "RSA"
                        try:
                            public_key_obj.verify(
                                st.session_state.signature_bytes_verify,
                                doc_hash_bytes_to_verify,
                                rsa_padding.PSS(
                                    mgf=rsa_padding.MGF1(hashes.SHA256()),
                                    salt_length=rsa_padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256()
                            )
                            verification_successful = True
                        except cryptography.exceptions.InvalidSignature:
                            error_detail = " (Fallo con RSA)"
                        except Exception as rsa_e:
                            error_detail = f" (Error con RSA: {rsa_e})"

                    # Intentar verificación ECDSA (si no fue exitosa con RSA o si la clave es EC)
                    if not verification_successful and isinstance(public_key_obj, ec.EllipticCurvePublicKey):
                        key_type_verified = "ECDSA"
                        try:
                            public_key_obj.verify(
                                st.session_state.signature_bytes_verify,
                                doc_hash_bytes_to_verify,
                                ec.ECDSA(hashes.SHA256())
                            )
                            verification_successful = True
                            error_detail = ""  # Limpiar error_detail si ECDSA tiene éxito
                        except cryptography.exceptions.InvalidSignature:
                            error_detail += " (Fallo con ECDSA)"
                        except Exception as ec_e:
                            error_detail += f" (Error con ECDSA: {ec_e})"

                    # Resultado final
                    if not verification_successful and key_type_verified == "Desconocido":
                        st.error(
                            f"❌ Tipo de clave pública no reconocido o no soportado. Solo se soportan claves RSA y ECDSA en formato PEM.{error_detail}")
                        rain(emoji="💥", font_size=80, falling_speed=5, animation_length=2)
                    elif verification_successful:
                        st.success(
                            f"✅ ¡LA FIRMA ES VÁLIDA! Verificada usando una clave {key_type_verified}. El documento es auténtico y no ha sido modificado desde que se firmó.")
                        st.balloons()
                    else:
                        st.error(
                            f"❌ ¡LA FIRMA NO ES VÁLIDA! No se pudo verificar con la clave {key_type_verified} proporcionada.{error_detail}")
                        rain(emoji="💥", font_size=80, falling_speed=5, animation_length=2)

            except ValueError as ve:
                st.error(f"Error al procesar la clave pública: {ve}. ¿Es un archivo PEM válido y sin encriptar?")
            except cryptography.exceptions.InvalidSignature:
                st.error(
                    "❌ ¡LA FIRMA NO ES VÁLIDA! La firma no corresponde al documento y la clave pública proporcionados.")
                rain(emoji="💥", font_size=80, falling_speed=5, animation_length=2)
            except Exception as e:
                st.error(f"Ocurrió un error inesperado durante la verificación: {e}")
