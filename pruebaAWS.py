from dotenv import load_dotenv # Es mejor importar específicamente lo que necesitas
import boto3
import os

from sympy import all_roots

from app_content import *

# Carga las variables de entorno UNA SOLA VEZ al inicio
load_dotenv()
print(os.getenv("AWS_ACCESS_KEY_ID")) # Para verificar que se cargó

s3 = boto3.client(
        "s3",
        region_name = "us-east-2"
)

# Define los nombres de archivo y bucket para evitar repeticiones
local_file_name = "TERMINOS-Y-CONDICIONES-GENERALES.pdf"
bucket_name = "bucket-weezing-bp"
s3_key = "media/TERMINOS-Y-CONDICIONES-GENERALES.pdf" # Ruta dentro del bucket

# Lee el archivo en bytes
try:
    with open(local_file_name, "rb") as f:
        file_bytes = f.read()
    print(f"Archivo '{local_file_name}' leído correctamente.")
except FileNotFoundError:
    print(f"Error: El archivo '{local_file_name}' no fue encontrado.")
    exit() # Salir si el archivo no existe

# Sube el objeto a S3
print(f"Subiendo '{s3_key}' a bucket '{bucket_name}'...")
s3.put_object(
    Bucket      = bucket_name,
    Key         = s3_key,
    Body        = file_bytes,
    ContentType = "application/pdf" # Importante para que el navegador sepa cómo tratarlo
)
print("Archivo subido a S3 exitosamente.")

# Genera la URL pre-firmada
print("Generando URL pre-firmada...")
url = s3.generate_presigned_url(
         "get_object", # Acción para la que se genera la URL
         Params={"Bucket": bucket_name,
                 "Key": s3_key},
         ExpiresIn=3600 # URL válida por 1 hora (3600 segundos)
)

firmantes = load_public_key_from_s3(all_roots())