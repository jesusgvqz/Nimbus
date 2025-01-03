# Nimbus
Plataforma basada en tecnologías web que permite la generación, firma, y verificación de archivos mediante llaves asimétricas.

Páginas

-Registro
-Login
-Firmar archivo
-Verificar archivo
-Renovar archivo

Manejador de base de datos SQLite
SQLite almacena los datos como un archivo físico en el sistema de archivos, lo que significa que la protección del archivo de base de datos es clave.Se implementara controles de acceso adecuados. SQLite no cuenta con soporte nativo para cifrado, pero se pueden usar extensiones como SQLCipher para proporcionar cifrado AES, lo que agrega una capa de seguridad crítica para proteger los datos almacenados.
Se realizará validación y saneamiento de las entradas de usuario es una práctica fundamental para prevenir inyección de SQL.
Se limitara el tamaño de la base de datos y evitar consultas innecesarias asegura que los recursos del sistema no sean agotados por ataques maliciosos, lo que ayuda a mantener la disponibilidad y estabilidad del servicio.
SQLite puede ser una opción segura si se sigue una estrategia de seguridad proactiva, haciendo énfasis en la protección de archivos, cifrado de datos y asegurando las configuraciones del sistema.

Creación del entorno

  python3 -m venv final
  cd final/
  source bin/activate
  pip install django
  django-admin startproject mysite
  
