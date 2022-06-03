
import socket
import threading
import sys
from time import sleep
from cryptography.hazmat.primitives import serialization
import mensajes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
from validaciones import validarEntradasCliente

USUARIO = 'pepito'
PASSWORD = 'pepito2022'


def conectar_servidor(host, puerto):
    # socket para IP v4
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((host, int(puerto)))
        return cliente
    except:
        print('Servidor inalcanzable')
        exit()


def leer_menu(cliente):
    """
    Lee el menú principal que manda el servidor y lo imprime.

    Keyword Arguments:
    cliente --
    returns: None
    """
    menu = mensajes.leer_mensaje(cliente)
    print(menu.decode('utf-8'))


def procesar_listar_archivos(cliente, comando):
    mensajes.mandar_mensaje(cliente, comando)
    respuesta = mensajes.leer_mensaje(cliente)
    print(respuesta.decode('utf-8'))
    mensajes.mandar_mensaje(cliente, b'Fin')


def procesar_descargar_archivo(cliente, comando, path_salida, aes_recibir):
    mensajes.mandar_mensaje(cliente, comando)
    mensaje = mensajes.leer_mensaje(cliente)
    if not b'OK' in mensaje:
        print(mensaje.decode('utf-8'))
        mensajes.mandar_mensaje(cliente, b'Fin')
        return
    nombre_archivo = comando.split(b' ')[1].strip()
    nombre_archivo = nombre_archivo.decode('utf-8')
    mensajes.mandar_mensaje(cliente, b'Continue')
    mensajes.leer_archivo(cliente, path_salida + '/' +
                          nombre_archivo, aes_recibir)
    mensajes.mandar_mensaje(cliente, b'Fin')


def procesar_subir_archivo(cliente, comando, aes_enviar):
    mensajes.mandar_mensaje(cliente, comando)
    mensaje = mensajes.leer_mensaje(cliente)
    if not b'OK' in mensaje:
        print(mensaje.decode('utf-8'))
        mensajes.mandar_mensaje(cliente, b'Fin')
        return
    path = comando.split(b' ')[1].strip()
    path = path.decode('utf-8')
    mensajes.mandar_archivo(cliente, path, aes_enviar)
    mensajes.leer_mensaje(cliente)
    mensajes.mandar_mensaje(cliente, b'Fin')


def procesar_comando(cliente, comando, path_ref, aes_enviar, aes_recibir):
    """
    Rutina para decidir las acciones a tomar de acuerdo al comando.

    Keyword Arguments:
    cliente --
    comando --
    returns: None
    """
    if comando.startswith(b'1'):
        procesar_listar_archivos(cliente, comando)
        return
    if comando.startswith(b'2'):
        procesar_descargar_archivo(cliente, comando, path_ref, aes_recibir)
        return
    if comando.startswith(b'3'):
        procesar_subir_archivo(cliente, comando, aes_enviar)
        return


def deserealizar_llave(llave):
    llave_deserealizada = serialization.load_pem_public_key(
        llave,
        backend=default_backend())
    return llave_deserealizada


def verificar_firma(ec_servidor_pub, signature, dh_servidor_pub_S):
    try:
        ec_servidor_pub.verify(
            signature, dh_servidor_pub_S, ec.ECDSA(hashes.SHA256()))
        print('**LA FIRMA ES VALIDA**')
    except:
        print('**LA FIRMA NO ES VALIDA**')
        exit()


def serializar_llave(llave):
    llave_serializada = llave.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return llave_serializada


def crear_secreto(dh_servidor_pub, dh_cliente_priv):
    secreto_emisor = dh_cliente_priv.exchange(ec.ECDH(), dh_servidor_pub)
    return secreto_emisor


def derivar_llave(secreto_emisor):
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data',  # tiene que ser lo mismo de los dos lados
                       backend=default_backend()).derive(secreto_emisor)
    return derived_key


def cifrar_sends(mensaje_plano, llave_aes):
    iv = os.urandom(12)
    aad = os.urandom(32)
    mp = mensaje_plano

    chacha = ChaCha20Poly1305(llave_aes)
    mensaje_cifrado = chacha.encrypt(iv, mp, aad)
    print(mensaje_cifrado)
    return (iv+aad+mensaje_cifrado)


def work_loop(cliente, path_ref, dh_cliente_pub):
    """
    Rutina con el loop de trabajo principal.

    Keyword Arguments:
    cliente socket
    returns: None
    """
    mensaje = mensajes.leer_mensaje(cliente)
    # * Esto solo ocurre una vez, cuando se inicia la conexión
    # // Si hay firmas al inicio del mensaje entonces pasa
    if mensaje.startswith(b'FIRMAS'):
        firmas = mensaje[6:]
        dh_servidor_pub_S = firmas[:215]
        ec_servidor_pub_S = firmas[215:430]
        signature = firmas[430:]

        ec_servidor_pub = deserealizar_llave(ec_servidor_pub_S)
        verificar_firma(ec_servidor_pub, signature, dh_servidor_pub_S)
        dh_cliente_pub_S = serializar_llave(dh_cliente_pub)
        dh_cliente_pub_S = b'DHCLIENTEPUB'+dh_cliente_pub_S

        dh_servidor_pub = deserealizar_llave(dh_servidor_pub_S)
        secreto_emisor = crear_secreto(dh_servidor_pub, dh_cliente_priv)
        secreto_enviar = secreto_emisor[:24]
        secreto_recibir = secreto_emisor[24:]

        aes_recibir = derivar_llave(secreto_recibir)
        aes_enviar = derivar_llave(secreto_enviar)
        """
        print('LLAVES CLIENTE::::')
        print(aes_recibir)
        print(aes_enviar)
        """
        llaveHKSF = derivar_llave(secreto_emisor[:32])
        # * CREDENCIALES
        mensaje = b'%s:%s' % (USUARIO.encode('utf-8'),
                              PASSWORD.encode('utf-8'))
        credenciales = cifrar_sends(mensaje, llaveHKSF)
        mensajes.mandar_mensaje(cliente,
                                dh_cliente_pub_S+b'::::'+credenciales)
    # // Si no pasa
    else:
        print('Faltan las firmas')
        exit(1)
    while True:
        # Intercambo ecdh
        # Enviar usuario y contraseña, debe ir protegido el envío
        # Autenticación del servidor (checar firma parte pública ecdh)
        leer_menu(cliente)
        comando = input('Selecciona comando: ')
        comando = comando.encode('utf-8')
        procesar_comando(cliente, comando, path_ref, aes_enviar, aes_recibir)


def crear_llaves_dh():
    dh_cliente_priv = ec.generate_private_key(
        ec.SECP384R1(), default_backend())
    # Esta es la que se tiene que intercambiar
    dh_cliente_pub = dh_cliente_priv.public_key()
    return dh_cliente_priv, dh_cliente_pub


if __name__ == '__main__':
    try:
        host = sys.argv[1]
        puerto = sys.argv[2]
        path_ref = sys.argv[3]
        validarEntradasCliente( host, puerto, path_ref )
        cliente = conectar_servidor(host, puerto)
        dh_cliente_priv, dh_cliente_pub = crear_llaves_dh()
        work_loop(cliente, path_ref, dh_cliente_pub)
    except IndexError:
        print( 'Error al ingresar parametros - Estructura: python cliente.py host puerto directorio_cliente' )
