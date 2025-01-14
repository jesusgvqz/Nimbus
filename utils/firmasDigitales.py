from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())

# notar que los datos son una cadena binaria
datos_a_firmar = b'Estos son mis datos autenticados'

# Notar que la firma es un objeto python, se puede convertir también
# a PEM como las llaves
signature = private_key.sign(datos_a_firmar,
                             ec.ECDSA(hashes.SHA256()))

public_key = private_key.public_key()

# Si la verificación no lanza execpción la firma es válida
try:
    public_key.verify(signature, datos_a_firmar, ec.ECDSA(hashes.SHA256()))
    print('La firma es válida')
except InvalidSignature:
    print('La firma es inválida')
