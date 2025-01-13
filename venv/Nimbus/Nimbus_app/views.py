from django.shortcuts import render # type: ignore

# Create your views here.

from Nimbus.imports import *
from utils.cifrar_aes import *
from utils.hasher import *
from .models import *

def registro(request):
    if request.method == "POST":
        nombre = request.POST.get("nombre")
        username = request.POST.get("username")
        password = request.POST.get("password")
        password_confirm = request.POST.get("passwordConfirmation")
        email = request.POST.get("email")

        # Validación básica
        if password != password_confirm:
            messages.error(request, "Las contraseñas no coinciden.")
            return render(request, "registro.html")

        # Validación de contraseña
        error_password = validar_password(password)
        if error_password:
            messages.error(request, error_password)
            return render(request, "registro.html")

        # Generación de llaves criptográficas
        llave_privada = generar_llave_privada()
        llave_publica = generar_llave_publica(llave_privada)

        llave_privada_binario = convertir_llave_privada_bytes(llave_privada)
        llave_publica_texto = convertir_llave_publica_bytes(llave_publica).decode("utf-8")

        # Cifrado de la llave privada
        iv = os.urandom(16)  # Vector de inicialización aleatorio
        llave_aes = generar_llave_aes_from_password(password)  # Derivamos la llave AES desde la contraseña
        llave_privada_cifrada = cifrar(llave_privada_binario, llave_aes, iv)

        # Guardar el IV, ya que es necesario para el descifrado
        iv_hex = iv.hex()  # Guardamos el IV como una cadena hex

        # Hash de la contraseña con salt
        salt = generar_salt()  # Generar un salt aleatorio
        password_hash = hash_contrasena(password, salt)  # Generar el hash de la contraseña

        # Debugging: Imprimir datos antes de la creación del usuario
        print(f"Nombre: {nombre}, Longitud: {len(nombre)}")
        print(f"Username: {username}, Longitud: {len(username)}")
        print(f"Password: {password_hash}, Longitud: {len(password_hash)}")
        print(f"Email: {email}, Longitud: {len(email)}")
        print(f"Salt: {salt}, Longitud: {len(salt)}")




        # Crear usuario
        try:
            usuario = Usuario.objects.create(
                nombre=nombre,
                username=username,
                password=password_hash,  # Almacena el hash de la contraseña
                salt=convertir_binario_texto64(salt),  # Almacena el salt en formato Base64
                email=email,
                private_key_encrypted=llave_privada_cifrada,  # Llave privada cifrada
                iv=iv_hex,  # Guardamos el IV en la base de datos
                public_key=llave_publica_texto  # Llave pública en texto plano
            )
            messages.success(request, "Usuario registrado con éxito.")
            return redirect('login')  # Redirige al login tras el registro
        except Exception as e:
            messages.error(request, f"Error al registrar el usuario: {str(e)}")
            return render(request, "registro.html")

    return render(request, "registro.html")

def generar_llave_privada():
    return ec.generate_private_key(ec.SECP384R1(), default_backend())

def generar_llave_publica(llave_privada):
    return llave_privada.public_key()

def convertir_llave_privada_bytes(llave_privada):
    return llave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def convertir_llave_publica_bytes(llave_publica):
    return llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Validación de contraseña
def validar_password(password):
    if len(password) < 12:
        return "La contraseña debe tener al menos 12 caracteres, al menos una letra mayúscula, al menos una letra minúscula y al menos un número."
    if not re.search(r'[A-Z]', password):
        return "La contraseña debe tener al menos 12 caracteres, al menos una letra mayúscula, al menos una letra minúscula y al menos un número."
    if not re.search(r'[a-z]', password):
        return "La contraseña debe tener al menos 12 caracteres, al menos una letra mayúscula, al menos una letra minúscula y al menos un número."
    if not re.search(r'[0-9]', password):
        return "La contraseña debe tener al menos 12 caracteres, al menos una letra mayúscula, al menos una letra minúscula y al menos un número."
    return None



def obtener_llave_privada_descifrada(usuario, password):
    # Recuperamos el IV de la base de datos y lo convertimos a binario
    iv = bytes.fromhex(usuario.iv)
    
    # Derivamos la llave AES usando la misma contraseña
    llave_aes = generar_llave_aes_from_password(password)
    
    # Desciframos la llave privada cifrada
    llave_privada_descifrada = descifrar(usuario.private_key_encrypted, llave_aes, iv)
    
    return llave_privada_descifrada


def verificar_contrasena(usuario, contrasena):
    # Convertir el salt almacenado de Base64 a binario
    salt = convertir_texto64_binario(usuario.salt)

    # Verificar la contraseña usando el hash y el salt almacenados
    if password_valido(contrasena, usuario.password, salt):
        return True
    else:
        return False
    
def login(request):
    t = 'login.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        usuario = request.POST.get('usuario', '').strip()
        password = request.POST.get('password', '').strip()
        errores = []

        # Validar que usuario y contraseña no estén vacíos
        if not usuario or not password:
            errores.append('El usuario o contraseña no pueden estar vacíos.')

        # Intentar obtener el usuario de la base de datos
        try:
            user = Usuario.objects.get(nombre=usuario)
        except Usuario.DoesNotExist:
            errores.append('Usuario o contraseña incorrectos.')
            return render(request, t, {'errores': errores})

        if errores:
            request.session['logueado'] = False
            return render(request, t, {'errores': errores})

        salt = convertir_texto64_binario(user.salt)  # Asumiendo que el salt está guardado en Base64
        password_hash = user.password  # El hash de la contraseña almacenado en la base de datos

        # Verificar la contraseña usando la función password_valido
        if not password_valido(password, password_hash, salt):
            errores.append('Usuario o contraseña incorrectos.')
            return render(request, t, {'errores': errores})
        
        # Si la contraseña es correcta, iniciar sesión
        request.session['logueado'] = True
        request.session['usuario'] = usuario
        return redirect('/menu')  

def menu(request):
    if not request.session.get('logueado', False):
        return redirect('login')  
    
    return render(request, 'menu.html')

@login_requerido
def firmar_archivo(request):
    if request.method == "POST":
        archivo = request.FILES.get("archivo")
        usuario = Usuario.objects.get(username=request.user.username)
        
        # Leer el contenido del archivo
        datos_a_firmar = archivo.read()

        # Descifrar la llave privada del usuario
        llave_privada_cifrada = usuario.private_key_encrypted
        iv = bytes.fromhex(usuario.iv)
        password = request.POST.get("password")  # Contraseña del usuario
        llave_aes = generar_llave_aes_from_password(password)
        
        try:
            llave_privada_binaria = descifrar(llave_privada_cifrada, llave_aes, iv)
            private_key = load_pem_private_key(llave_privada_binaria, password=None, backend=default_backend())

            # Firmar los datos
            signature = private_key.sign(datos_a_firmar, ec.ECDSA(hashes.SHA256()))

            # Convertir la firma a Base64 para devolverla como respuesta
            firma_base64 = base64.b64encode(signature).decode("utf-8")
            
            return render(request, "firmar_archivo.html", {
                "firma": firma_base64,
                "mensaje": "Archivo firmado exitosamente.",
            })

        except Exception as e:
            return render(request, "firmar_archivo.html", {
                "error": f"Error al firmar el archivo: {str(e)}"
            })

    return render(request, "firmar_archivo.html")

def verificar_archivo(request):

    return render(request, 'verificar_archivo.html')

def renovar_llave(request):
    return render(request, 'renovar_llave.html')