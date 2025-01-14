import hashlib
import os
import base64

def generar_salt():
    """Genera un salt aleatorio de 16 bytes"""
    return os.urandom(16)

def hash_contrasena(password, salt):
    """Genera un hash SHA-512 de la contraseña con un salt"""
    password_combined = password.encode('utf-8') + salt
    hasher = hashlib.sha512()
    hasher.update(password_combined)
    return hasher.hexdigest()

def password_valido(password, hash_almacenado, salt_almacenado):
    """Verifica si la contraseña es válida comparando el hash calculado con el hash almacenado"""
    password_combined = password.encode('utf-8') + salt_almacenado
    hasher = hashlib.sha512()
    hasher.update(password_combined)
    return hash_almacenado == hasher.hexdigest()

def convertir_binario_texto64(binario):
    """Convierte datos binarios a texto Base64"""
    return base64.b64encode(binario).decode('utf-8')

def convertir_texto64_binario(texto64):
    """Convierte texto Base64 a binario"""
    return base64.b64decode(texto64)