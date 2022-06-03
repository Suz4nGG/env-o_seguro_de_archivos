from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
from cryptography. hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography . hazmat . primitives . ciphers . aead import AESGCM


def encriptar(data, key, nonce):
    #aesgcm = AESGCM(key)
    #ct = aesgcm.encrypt(nonce, data, nonce)
    #return ct
    encryptor = Cipher(algorithms.AES(key),
                modes.GCM(nonce),
                backend = default_backend()).encryptor()
    associated_data = nonce + nonce
    encryptor.authenticate_additional_data(associated_data)
    ct = encryptor.update(data)
    encryptor.finalize() # necesario para generar tag
    tag = encryptor.tag # 16 bytes
    return ct,tag


# key es de 128

def desencriptar(key, ct, nonce):
    aesgcm = AESGCM(key)
    plain = aesgcm.decrypt(nonce, ct, nonce)
    return plain


