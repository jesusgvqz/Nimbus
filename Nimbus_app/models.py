from django.db import models # type: ignore
from utils.generarLlaves import *
from datetime import timedelta
from django.utils.timezone import now # type: ignore

class Usuario(models.Model):
    nombre=models.CharField(max_length=70, unique=True)
    username = models.CharField(max_length=100, unique=True, null=True)
    password = models.CharField(max_length=128)   
    email= models.CharField(max_length=70, unique=True, default="usuario@uv.mx" )
    private_key_encrypted = models.BinaryField(default=b'')
    public_key = models.TextField(null=True)
    iv = models.CharField(max_length=32, null=True)  
    salt = models.CharField(max_length=64, null=True) 
    updated_at = models.DateTimeField(auto_now=True)  # Última vez que se renovaron las llaves

    def llaves_expiradas(self):
        # Calcula si han pasado más de 10 minutos desde la última actualización
        tiempo_generacion = self.updated_at
        return now() > tiempo_generacion + timedelta(minutes=10)

# Create your models here.
