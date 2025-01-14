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
            user = Usuario.objects.get(username=usuario)  # Cambié de 'nombre' a 'username'
        except Usuario.DoesNotExist:
            errores.append('Usuario o contraseña incorrectos.')
            return render(request, t, {'errores': errores})

        # Validar errores antes de seguir
        if errores:
            request.session['logueado'] = False
            return render(request, t, {'errores': errores})

        # Verificar la contraseña
        salt = convertir_texto64_binario(user.salt)  # Convertir el salt almacenado
        password_hash = user.password  # Hash almacenado en la base de datos

        if not password_valido(password, password_hash, salt):  # Validar la contraseña
            errores.append('Usuario o contraseña incorrectos.')
            return render(request, t, {'errores': errores})
        
        # Si la contraseña es correcta, iniciar sesión
        request.session['logueado'] = True
        request.session['usuario'] = user.username  # Guardar el username en la sesión
        
        return redirect('/menu')

    

def logout(request):
    # Limpiar la sesión
    request.session.flush()
    # Redirigir al login
    return redirect('/login/')


def menu(request):
    if not request.session.get('logueado', False):
        return redirect('login')  
    
    usuario = Usuario.objects.get(username=request.session['usuario'])
    mensaje = None
    if usuario.llaves_expiradas():
        mensaje = "Tus llaves han expirado. Por favor, renuévalas antes de realizar cualquier acción."
    
    return render(request, 'menu.html', {"mensaje": mensaje})


@login_requerido
def firmar_archivo(request):
    if request.method == "POST":
        archivo = request.FILES.get("archivo")
        usuario = Usuario.objects.get(username=request.session['usuario'])
        
        # Verificar si las llaves están expiradas
        if usuario.llaves_expiradas():
            return render(request, "firmar_archivo.html", {
                "error": "Tus llaves han expirado. Por favor, renuévalas para continuar."
            })

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

            # Crear un archivo descargable con la firma
            response = HttpResponse(signature, content_type="application/octet-stream")
            response["Content-Disposition"] = f"attachment; filename={archivo.name}.sig"
            return response

        except Exception as e:
            return render(request, "firmar_archivo.html", {
                "error": f"Error al firmar el archivo: {str(e)}"
            })

    return render(request, "firmar_archivo.html")

@login_requerido
def verificar_archivo(request):
    if request.method == "POST":
        archivo = request.FILES.get("archivo")
        firma = request.FILES.get("firma")
        username_firmante = request.POST.get("username_firmante")

        try:

            # Obtener el usuario actual
            usuario_actual = Usuario.objects.get(username=request.session['usuario'])

            # Verificar si las llaves del usuario actual han expirado
            if usuario_actual.llaves_expiradas():
                return render(request, "verificar_archivo.html", {
                    "error": "Tus llaves han expirado. Por favor, renuévalas para continuar."
                })

            # Obtener el usuario firmante
            usuario_firmante = Usuario.objects.get(username=username_firmante)
            llave_publica = usuario_firmante.public_key
            
            # Leer contenido del archivo y la firma
            datos_a_verificar = archivo.read()
            firma_binaria = firma.read()
            
            # Cargar la llave pública
            public_key = load_pem_public_key(llave_publica.encode("utf-8"), backend=default_backend())
            
            # Verificar la firma
            try:
                public_key.verify(firma_binaria, datos_a_verificar, ECDSA(SHA256()))
                mensaje = "La firma es válida y el archivo no ha sido alterado."
            except InvalidSignature:
                mensaje = "La firma no es válida o el archivo ha sido alterado."
            
            return render(request, "verificar_archivo.html", {
                "mensaje": mensaje
            })

        except Usuario.DoesNotExist:
            return render(request, "verificar_archivo.html", {
                "error": "El usuario firmante no existe."
            })
        except Exception as e:
            return render(request, "verificar_archivo.html", {
                "error": f"Error al verificar la firma: {str(e)}"
            })

    return render(request, "verificar_archivo.html")

@login_requerido
def renovar_llave(request):
    if request.method == "POST":
        try:
            usuario = Usuario.objects.get(username=request.session['usuario'])

            # Generar nuevo par de llaves
            private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            public_key = private_key.public_key()

            # Serializar la llave pública
            public_key_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")

            # Serializar la llave privada
            private_key_pem = private_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            )

            # Cifrar la nueva llave privada con AES
            password = request.POST.get("password")
            if not password:
                return render(request, "renovar_llave.html", {
                    "error": "La contraseña es requerida para renovar la llave."
                })

            llave_aes = generar_llave_aes_from_password(password)
            iv = os.urandom(16)  # Generar un IV aleatorio de 16 bytes
            llave_privada_cifrada = cifrar(private_key_pem, llave_aes, iv)

            # Actualizar las llaves del usuario en la base de datos
            usuario.private_key_encrypted = llave_privada_cifrada
            usuario.public_key = public_key_pem
            usuario.iv = iv.hex()
            usuario.save()

            return render(request, "renovar_llave.html", {
                "mensaje": "Llaves renovadas exitosamente."
            })

        except Exception as e:
            return render(request, "renovar_llave.html", {
                "error": f"Error al renovar las llaves: {str(e)}"
            })

    return render(request, "renovar_llave.html")