# Nimbus

En el contexto actual de la tecnología y la seguridad informática, la protección de la integridad y autenticidad de los datos es fundamental, especialmente cuando se trata de archivos que se intercambian a través de medios no seguros, como el correo electrónico. En este sentido, las firmas digitales desempeñan un papel crucial al garantizar que los archivos no hayan sido modificados y provengan de una fuente confiable.
Este proyecto final tiene como objetivo el desarrollo de una plataforma web segura que permita la gestión y generación de llaves privadas asimétricas para la firma y verificación de archivos. Los usuarios de la plataforma podrán subir archivos y obtener una firma digital, asegurando así la autenticidad e integridad del archivo en cuestión, sin necesidad de almacenar los archivos en el servidor. La solución proporcionada también permitirá a los usuarios verificar la validez de firmas de archivos generados por otros usuarios, utilizando las llaves públicas correspondientes.
Este proyecto no solo tiene como objetivo demostrar la aplicación de tecnologías de cifrado y firmas digitales, sino también poner en práctica los conocimientos adquiridos sobre desarrollo seguro de aplicaciones web, con un enfoque especial en la protección de la información sensible y la autenticidad de los datos manejados.

## Páginas

-Registro
-Login
-Firmar archivo
-Verificar archivo
-Renovar llave

## Manejador de base de datos SQLite
SQLite almacena los datos como un archivo físico en el sistema de archivos, lo que significa que la protección del archivo de base de datos es clave.Se implementara controles de acceso adecuados. SQLite no cuenta con soporte nativo para cifrado, pero se pueden usar extensiones como SQLCipher para proporcionar cifrado AES, lo que agrega una capa de seguridad crítica para proteger los datos almacenados.
Se realizará validación y saneamiento de las entradas de usuario es una práctica fundamental para prevenir inyección de SQL.
Se limitara el tamaño de la base de datos y evitar consultas innecesarias asegura que los recursos del sistema no sean agotados por ataques maliciosos, lo que ayuda a mantener la disponibilidad y estabilidad del servicio.
SQLite puede ser una opción segura si se sigue una estrategia de seguridad proactiva, haciendo énfasis en la protección de archivos, cifrado de datos y asegurando las configuraciones del sistema.

## Política de contraseñas
  Para garantizar la seguridad de tu cuenta en nuestro sitio, hemos establecido los siguientes requisitos para las contraseñas:

Longitud mínima: La contraseña debe tener al menos 12 caracteres.

La contraseña debe contener al menos:
  1 letra mayúscula (A-Z).
  1 letra minúscula (a-z).
  1 número (0-9).
Se recomienda evitar contraseñas fáciles de adivinar, como nombres comunes, fechas de nacimiento, o secuencias de caracteres simples.
Se recomienda usar contraseñas únicas para cada cuenta.
Mantén tu contraseña segura y no la compartas con nadie. Si sospechas que tu contraseña ha sido comprometida, cámbiala inmediatamente.
