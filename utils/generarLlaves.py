from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import sys

"""
Ejemplo de generación de llaves mediante curvas elipticas
generar_llave_privada y generar_llave_publica regresan contenido binario
El resto de las funciones es para codificar y decodificar el contenido binario
a formato PEM (texto)
"""


def generar_llave_privada():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return private_key


def generar_llave_publica(llave_privada):
    return llave_privada.public_key()


def convertir_llave_privada_bytes(llave_privada):
    """
    Convierte de bytes a PEM
    """
    resultado = llave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return resultado


def convertir_bytes_llave_privada(contenido_texto):
    """
    Convierte de PEM a bytes
    """
    resultado = serialization.load_pem_private_key(
        contenido_texto,
        backend=default_backend(),
        password=None)
    return resultado


def convertir_llave_publica_bytes(llave_publica):
    resultado = llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return resultado


def convertir_bytes_llave_publica(contenido_texto):
    resultado = serialization.load_pem_public_key(
        contenido_texto,
        backend=default_backend())
    return resultado


# Ejemplo de uso de funciones para guardar llaves en formato PEM
if __name__ == '__main__':
    path_salida_privada = sys.argv[1]
    path_salida_publica = sys.argv[2]

    llave_privada = generar_llave_privada()
    llave_publica = generar_llave_publica(llave_privada)

    with open(path_salida_privada, 'wb') as salida_privada:
        contenido = convertir_llave_privada_bytes(llave_privada)
        salida_privada.write(contenido)

    with open(path_salida_publica, 'wb') as salida_publica:
        contenido = convertir_llave_publica_bytes(llave_publica)
        salida_publica.write(contenido)
