
import hashlib
import os
import base64

salt = os.urandom(16)
passwor_original = 'Mi Pass'.encode('utf-8')
password = passwor_original + salt
hasher = hashlib.sha512()
hasher.update(password)
mi_hash = hasher.hexdigest()


def password_valido(password, hash_almacenado, salt_almacenado):
    passwor_original = password.encode('utf-8')
    password = passwor_original + salt_almacenado
    hasher = hashlib.sha512()
    mi_hash = hasher.update(password).hexdigest()
    return hash_almacenado == mi_hash


def convertir_binario_texto64(binario):
    return base64.b64encode(binario).decode('utf-8')


def convertir_texto64_binario(texto64):
    return base64.b64decode(texto64)
