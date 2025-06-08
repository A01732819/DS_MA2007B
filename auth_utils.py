# auth_utils.py

import streamlit as st # Todavía útil para st.error si algo sale mal
import hashlib
import os
import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# Esto debe hacerse ANTES de que boto3 intente acceder a las credenciales.
load_dotenv()

S3_AUTH_BUCKET_NAME = os.getenv("S3_AUTH_BUCKET_NAME")
S3_AUTH_REGION = os.getenv("S3_AUTH_REGION", "us-east-2") # Default si no está en .env
USERS_FILE_KEY = os.getenv("S3_AUTH_USERS_FILE", "auth/users.json") # Default

s3_client = None
initialization_error = None

if not S3_AUTH_BUCKET_NAME:
    initialization_error = "La variable de entorno S3_AUTH_BUCKET_NAME no está configurada."
    # st.error(initialization_error) # No se puede usar st.error aquí directamente porque el módulo se carga antes que la app
    print(f"ERROR en auth_utils: {initialization_error}") # Imprime a consola
else:
    try:
        # Boto3 usará las credenciales (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        # cargadas por load_dotenv() desde tu archivo .env.
        # Si AWS_SESSION_TOKEN es necesario (ej. para roles IAM temporales), también lo tomará del env.
        s3_client = boto3.client(
            's3',
            region_name=S3_AUTH_REGION
            # No necesitas pasar aws_access_key_id ni aws_secret_access_key explícitamente
            # si están correctamente en las variables de entorno.
        )
        # Pequeña prueba para ver si las credenciales son válidas (opcional pero útil)
        s3_client.list_buckets() # Esto fallará si las credenciales no son válidas
        print(f"Cliente S3 inicializado correctamente para autenticación. Bucket: {S3_AUTH_BUCKET_NAME}, Región: {S3_AUTH_REGION}")
    except NoCredentialsError:
        initialization_error = "Credenciales de AWS no encontradas. Asegúrate de que AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY estén en tu .env."
        print(f"ERROR en auth_utils: {initialization_error}")
    except ClientError as e:
        if "InvalidClientTokenId" in str(e) or "SignatureDoesNotMatch" in str(e):
            initialization_error = "Credenciales de AWS inválidas. Revisa tu .env."
        else:
            initialization_error = f"Error de cliente Boto3 al inicializar S3: {e}"
        print(f"ERROR en auth_utils: {initialization_error}")
    except Exception as e:
        initialization_error = f"Error inesperado al inicializar el cliente S3: {e}"
        print(f"ERROR en auth_utils: {initialization_error}")


# --- Funciones de Hash y Autenticación (sin cambios) ---
def generate_salt():
    return os.urandom(16).hex()

def hash_password(password, salt):
    salted_password = salt.encode() + password.encode()
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def verify_password(stored_hash, stored_salt, provided_password):
    return stored_hash == hash_password(provided_password, stored_salt)

# --- Funciones de S3 para Usuarios (adaptadas para usar el s3_client y variables del módulo) ---
def load_users_from_s3():
    if initialization_error:
        st.error(f"No se pueden cargar usuarios: {initialization_error}")
        return {}
    if not s3_client:
        st.error("Cliente S3 no inicializado. Verifica la configuración y credenciales.")
        return {}
    try:
        response = s3_client.get_object(Bucket=S3_AUTH_BUCKET_NAME, Key=USERS_FILE_KEY)
        users_data = json.loads(response['Body'].read().decode('utf-8'))
        return users_data
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return {} # El archivo no existe aún, es normal al principio
        else:
            st.error(f"Error al cargar usuarios desde S3 ({S3_AUTH_BUCKET_NAME}/{USERS_FILE_KEY}): {e}")
            return {}
    except Exception as e:
        st.error(f"Error inesperado al cargar usuarios: {e}")
        return {}

def save_users_to_s3(users_data):
    if initialization_error:
        st.error(f"No se pueden guardar usuarios: {initialization_error}")
        return False
    if not s3_client:
        st.error("Cliente S3 no inicializado. Verifica la configuración y credenciales.")
        return False
    try:
        s3_client.put_object(
            Bucket=S3_AUTH_BUCKET_NAME,
            Key=USERS_FILE_KEY,
            Body=json.dumps(users_data, indent=4),
            ContentType='application/json'
        )
        # st.toast("Datos de usuario guardados en S3.") # Opcional para feedback
        return True
    except ClientError as e:
        st.error(f"Error de cliente S3 al guardar usuarios ({S3_AUTH_BUCKET_NAME}/{USERS_FILE_KEY}): {e}")
        return False
    except Exception as e:
        st.error(f"Error inesperado al guardar usuarios en S3: {e}")
        return False


# En auth_utils.py o un nuevo s3_key_storage.py

# (asumiendo que s3_client y S3_AUTH_BUCKET_NAME ya están definidos como antes)

KEY_STORAGE_PATH_PREFIX = "user_keys"  # Carpeta en S3 para las claves


def save_public_key_to_s3(username, public_key_pem_bytes, key_type="RSA"):
    """
    Guarda la clave pública (PEM en bytes) de un usuario en S3, distinguiendo por tipo de clave.

    Args:
        username (str): El nombre de usuario.
        public_key_pem_bytes (bytes): La clave pública en formato PEM como bytes.
        key_type (str): El tipo de clave, ej. "RSA" o "ECDSA". Usado para el nombre del archivo.

    Returns:
        bool: True si se guardó exitosamente, False en caso contrario.
    """
    if initialization_error or not s3_client:
        st.error("Error de S3: No se puede guardar la clave pública debido a un problema de inicialización del sistema.")
        print(f"DEBUG (save_public_key_to_s3): S3 no inicializado. Error: {initialization_error}")
        return False
    if not username:
        st.error("Error: Se requiere nombre de usuario para guardar la clave pública.")
        print("ERROR (save_public_key_to_s3): Username no provisto.")
        return False
    if not public_key_pem_bytes:
        st.error("Error: No hay datos de clave pública para guardar.")
        print("ERROR (save_public_key_to_s3): public_key_pem_bytes está vacío.")
        return False

    key_type_upper = key_type.upper() # Asegurar consistencia en mayúsculas para el nombre
    filename = f"public_key_{key_type_upper}.pem"
    key_path = f"{KEY_STORAGE_PATH_PREFIX}/{username}/{filename}"

    try:
        s3_client.put_object(
            Bucket=S3_AUTH_BUCKET_NAME,
            Key=key_path,
            Body=public_key_pem_bytes,
            ContentType='application/x-pem-file' # O 'text/plain' si es más genérico para PEM
        )
        st.success(f"Clave pública {key_type_upper} para '{username}' guardada exitosamente en S3 como '{filename}'.")
        print(f"INFO (save_public_key_to_s3): Clave {key_path} guardada en bucket {S3_AUTH_BUCKET_NAME}.")
        return True
    except ClientError as e:
        st.error(f"Error de AWS S3 al guardar la clave pública {key_type_upper} para '{username}': {e}")
        print(f"ERROR (save_public_key_to_s3): ClientError para {key_path} - {e}")
        return False
    except Exception as e:
        st.error(f"Error inesperado al guardar la clave pública {key_type_upper} para '{username}' en S3: {e}")
        print(f"ERROR (save_public_key_to_s3): Excepción inesperada para {key_path} - {e}")
        return False

def load_public_key_from_s3(username, key_type):
    """
    Carga la clave pública (PEM en bytes) de un usuario desde S3, distinguiendo por tipo de clave.

    Args:
        username (str): El nombre de usuario.
        key_type (str): El tipo de clave a cargar, ej. "RSA" o "ECDSA".

    Returns:
        bytes or None: La clave pública en formato PEM como bytes si se encuentra, o None si no existe o hay un error.
    """
    if initialization_error or not s3_client:
        st.error("Error de S3: No se puede cargar la clave pública debido a un problema de inicialización del sistema.")
        print(f"DEBUG (load_public_key_from_s3): S3 no inicializado. Error: {initialization_error}")
        return None
    if not username:
        # No mostramos error de UI aquí, ya que podría ser un chequeo silencioso
        print("DEBUG (load_public_key_from_s3): Username no provisto, no se puede cargar clave.")
        return None

    key_type_upper = key_type.upper()
    filename = f"public_key_{key_type_upper}.pem"
    key_path = f"{KEY_STORAGE_PATH_PREFIX}/{username}/{filename}"

    try:
        response = s3_client.get_object(Bucket=S3_AUTH_BUCKET_NAME, Key=key_path)
        public_key_pem_bytes = response['Body'].read()
        # st.info(f"Clave pública {key_type_upper} para '{username}' cargada desde S3.") # Opcional, puede ser ruidoso
        print(f"INFO (load_public_key_from_s3): Clave {key_path} cargada desde bucket {S3_AUTH_BUCKET_NAME}.")
        return public_key_pem_bytes
    except ClientError as e:
        if hasattr(e, 'response') and e.response.get('Error', {}).get('Code') == 'NoSuchKey':
            # Es normal si el usuario no ha guardado este tipo de clave. No es un error de UI necesariamente.
            print(f"INFO (load_public_key_from_s3): No se encontró la clave {key_path} en S3 para '{username}'.")
            return None
        else:
            st.error(f"Error al cargar la clave pública {key_type_upper} de '{username}' desde S3: {e}")
            print(f"ERROR (load_public_key_from_s3): ClientError para {key_path} - {e}")
            return None
    except Exception as e:
        st.error(f"Error inesperado al cargar la clave pública {key_type_upper} de '{username}' desde S3: {e}")
        print(f"ERROR (load_public_key_from_s3): Excepción inesperada para {key_path} - {e}")
        return None
