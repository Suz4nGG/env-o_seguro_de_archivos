"""
Módulo con la implementación del servidor de archivos

-No tiene seguridad integrada
-Está limitado a poder atender sólo a un cliente a la vez

"""

import socket
from time import sleep
import threading
import sys
import os
import functools
from cliente import PASSWORD
import mensajes
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from validaciones import validarEntradasServidor

USUARIOS = {'pepito': 'pepito2022', 'juanito': 'nada'}


def crear_socket_servidor(puerto):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # hace el bind en cualquier interfaz disponible
    servidor.bind(('', int(puerto)))
    return servidor


def listar_archivos(directorio_path):
    lista_archivos = os.listdir(directorio_path)
    lista_binaria = [ar.encode('utf-8') for ar in lista_archivos]
    res = functools.reduce(lambda s1, s2: s1 + b'\n' + s2, lista_binaria)
    return res


def enviar_lista_archivos(cliente, directorio):
    mensajes.mandar_mensaje(cliente, listar_archivos(directorio))


def regregar_menu_usuario():
    return b"""
    Opciones disponibles:
    1) Listar archivos (ejemplo: 1)
    2) Descargar archivo (indicar nombre, ejemplo: 2 arichivo.txt)
    3) Subir archivo (indicar ruta local, ejemplo: 3 /path/archivo)
    """


def descargar_archivo(cliente, directorio_repositorio, mensaje,aes_enviar):
    """
    Funcionalidad para que los clientes descarguen un archivo.

    Keyword Arguments:
    cliente                --
    directorio_repositorio --
    mensaje                Mensaje leído de cliente con params
    returns: None
    """
    partes = mensaje.split(b' ')
    if len(partes) != 2:
        mensajes.mandar_mensaje(cliente, b'Malos argumentos')
        return
    nombre_archivo = partes[1].strip()
    nombre_archivo = nombre_archivo.decode('utf-8')
    if not nombre_archivo in os.listdir(directorio_repositorio):
        mensajes.mandar_mensaje(cliente, b'No existe el archivo')
        return
    mensajes.mandar_mensaje(cliente, b'OK')
    mensajes.leer_mensaje(cliente)
    mensajes.mandar_archivo(
        cliente, directorio_repositorio + '/' + nombre_archivo,aes_enviar)


def subir_achivo(cliente, directorio_repositorio, mensaje,aes_recibir): ##############
    """
    Funcionalidad para que los clientes puedan subir archivos al repo.

    Keyword Arguments:
    cliente                --
    directorio_repositorio --
    mensaje                --
    returns: None
    """
    partes = mensaje.split(b' ')
    if len(partes) != 2:
        mensajes.mandar_mensaje(cliente, b'Malos argumentos')
        return
    nombre_archivo = partes[1].strip()
    nombre_archivo = nombre_archivo.decode('utf-8')
    nombre_archivo = nombre_archivo.split('/')[-1].strip()
    if nombre_archivo in os.listdir(directorio_repositorio):
        mensajes.mandar_mensaje(cliente, b'Ya existe el archivo')
        return
    mensajes.mandar_mensaje(cliente, b'OK')
    mensajes.leer_archivo(cliente, directorio_repositorio + '/' +
                          nombre_archivo,aes_recibir)
    mensajes.mandar_mensaje(cliente, b'OK')


def leer_opcion(cliente, directorio_repositorio,aes_recibir,aes_enviar):
    """
    Determina la acción de cliente a ejecutar.

    Keyword Arguments:
    cliente --
    returns: None
    """
    mensaje = mensajes.leer_mensaje(cliente)
    if mensaje.startswith(b'1'):
        enviar_lista_archivos(cliente, directorio_repositorio)
    if mensaje.startswith(b'2'):
        descargar_archivo(cliente, directorio_repositorio, mensaje,aes_enviar)
    if mensaje.startswith(b'3'):
        subir_achivo(cliente, directorio_repositorio, mensaje,aes_recibir)
    resultado = mensajes.leer_mensaje(cliente)
    print(resultado.decode('utf-8'))


def deserealizar_llave(llave):
    llave_deserealizada = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    return llave_deserealizada


def crear_secreto(dh_cliente_pub, dh_servidor_priv):
    secreto_emisor = dh_servidor_priv.exchange(ec.ECDH(), dh_cliente_pub)

    return secreto_emisor


def derivar_llave(secreto_receptor):
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data',  # tiene que ser lo mismo de los dos lados
                       backend=default_backend()).derive(secreto_receptor)
    return derived_key


def descifrar_recvs(mensaje_cifrado, llave_aes):
    """
    print('MENSAJE DECIFRADO')
    print(mensaje_cifrado)
    """
    iv = mensaje_cifrado[0:12]
    mensaje_cifrado = mensaje_cifrado[12:]
    aad = mensaje_cifrado[0:32]
    mensaje_cifrado = mensaje_cifrado[32:]
    mc = mensaje_cifrado
    chacha = ChaCha20Poly1305(llave_aes)
    mensaje = chacha.decrypt(iv, mc, aad)
    return mensaje


def atencion(cliente, directorio_repositorio):
    mensaje = mensajes.leer_mensaje(cliente)
    if mensaje.startswith(b'DHCLIENTEPUB'):
        dh_cliente_pub_S = mensaje[12:]
        dh_cliente_pub = deserealizar_llave(dh_cliente_pub_S)
        secreto_receptor = crear_secreto(dh_cliente_pub, dh_servidor_priv)
        secreto_recibir = secreto_receptor[:24]
        secreto_enviar = secreto_receptor[24:]

        aes_recibir = derivar_llave(secreto_recibir)
        aes_enviar = derivar_llave(secreto_enviar)
        """
        print('LLAVES SERVIDOR::::')
        print(aes_recibir)
        print(aes_enviar)
        """
        llaveHKDF = derivar_llave(secreto_receptor[:32])
        credenciales = mensaje[-77:]
        credenciales_des = descifrar_recvs(credenciales,
                                           llaveHKDF)
        credencialesU = credenciales_des.decode('utf-8')
        username = credencialesU.split(':')[0]
        password = credencialesU.split(':')[1]
        if username in USUARIOS.keys():
            print('ENTRO')
    while True:
        mensajes.mandar_mensaje(cliente, regregar_menu_usuario())
        leer_opcion(cliente, directorio_repositorio,aes_recibir,aes_enviar)


def serializar_llave(llave):
    llave_serializada = llave.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return llave_serializada


def escuchar(servidor, directorio_repositorio, dh_servidor_priv, dh_servidor_pub):
    servidor.listen(5)  # peticiones de conexion simultaneas
    while True:
        cliente, _ = servidor.accept()  # bloqueante, hasta que llegue una peticion
        dh_servidor_pub_S = serializar_llave(dh_servidor_pub)
        ec_servidor_pub_S = serializar_llave(ec_servidor_pub)
        signature = ec_servidor_priv.sign(
            dh_servidor_pub_S, ec.ECDSA(hashes.SHA256()))
        firmas = b'FIRMAS' + dh_servidor_pub_S + ec_servidor_pub_S + signature
        mensajes.mandar_mensaje(cliente, firmas)

        hiloAtencion = threading.Thread(target=atencion, args=(
            cliente, directorio_repositorio))  # se crea un hilo de atención por cliente
        hiloAtencion.start()


def crear_llaves_dh():
    dh_servidor_priv = ec.generate_private_key(
        ec.SECP384R1(), default_backend())
    # Esta es la que se tiene que intercambiar
    dh_servidor_pub = dh_servidor_priv.public_key()
    return dh_servidor_priv, dh_servidor_pub


def crear_llaves_ec():
    ec_servidor_priv = ec.generate_private_key(
        ec.SECP384R1(), default_backend())
    ec_servidor_pub = ec_servidor_priv.public_key()
    return ec_servidor_priv, ec_servidor_pub


# * Serializao de las llaves
def convertir_llave_privada_bytes(llave_privada):
    resultado = llave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return resultado


# * Convertenimos bytes de la llave privada del servidor
def convertir_bytes_llave_privada(contenido_binario):
    resultado = serialization.load_pem_private_key(
        contenido_binario,
        backend=default_backend(),
        password=None)
    return resultado


# * Regresamos los bytes
def regresar_bytes(path_archivo):
    contenido = ''
    with open(path_archivo, 'rb') as archivo:
        contenido = archivo.read()
    return contenido


if __name__ == '__main__':
    try:
        puerto = sys.argv[1]
        repositorio_path = sys.argv[2]
        # Validar entradas
        validarEntradasServidor( puerto, repositorio_path )
        servidor = crear_socket_servidor(puerto)
        print('Escuchando...')
        # * Establecemos la sesión segura aquí, creando las llaves EC
        ec_servidor_priv, ec_servidor_pub = crear_llaves_ec()
        # * Serializamos la llave pública del servidor
        dh_servidor_priv, dh_servidor_pub = crear_llaves_dh()
        escuchar(servidor, repositorio_path, dh_servidor_priv, dh_servidor_pub)
    except IndexError:
        print( 'Error al ingresar parametros - Estructura: python servidor.py puerto directorio_servidor' )