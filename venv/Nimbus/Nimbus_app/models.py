from django.db import models # type: ignore

class Usuario(models.Model):
    nombre=models.CharField(max_length=70, unique=True)
    username = models.CharField(max_length=100, unique=True, null=True)
    password = models.CharField(max_length=128)   
    email= models.CharField(max_length=70, unique=True, default="usuario@uv.mx" )
    private_key_encrypted = models.BinaryField(default=b'')
    public_key = models.TextField(null=True)
    iv = models.CharField(max_length=32, null=True)  
    salt = models.CharField(max_length=64, null=True) 
# Create your models here.
