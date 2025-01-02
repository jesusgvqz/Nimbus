from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def generar_llave_aes_from_password(password):
    password = password.encode('utf-8')
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data ',
                       backend=default_backend()).derive(password)
    return derived_key


def cifrar(mensaje, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    cifrador = aesCipher.encryptor()
    cifrado = cifrador.update(mensaje)
    cifrador.finalize()
    return cifrado


def descifrar(cifrado, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    descifrador = aesCipher.decryptor()
    plano = descifrador.update(cifrado)
    descifrador.finalize()
    return plano


# Demo
if __name__ == '__main__':
    # notar que el contenido debe ser binario siempre
    contenido_secreto = b'Este contenido es privado'
    mi_password = 'ContraseñaFuerte'
    # derivar una llave de 32 bits del password
    llave_aes = generar_llave_aes_from_password(mi_password)
    # el iv es binario y debe guardarse en algún lado para poder descifrar
    # el iv no es secreto, se guarda de forma plana
    iv = os.urandom(16)
    cifrado = cifrar(contenido_secreto, llave_aes, iv)
    print(cifrado)

    # se debe usar la misma llave_aes e iv
    descifrado = descifrar(cifrado, llave_aes, iv)
    print(descifrado)
