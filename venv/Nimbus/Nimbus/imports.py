# config.py

# === Importaciones de Django ===
from django.http import HttpResponse # type: ignore
from django.template import Template, Context # type: ignore
from django.shortcuts import render, redirect # type: ignore
from django.contrib.auth.hashers import make_password # type: ignore
from django.contrib.auth.hashers import check_password # type: ignore
from django.contrib import messages # type: ignore
from .decoradores import login_requerido

# === Importaciones de modelos ===
from Nimbus_app import models
from Nimbus_app.models import Usuario
from Nimbus import decoradores

# === Importaciones de cryptography ===
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from django.contrib.auth.decorators import login_required  # type: ignore


# === Importaciones generales ===
import Nimbus.settings as conf
import os
import hashlib
import base64
import re
