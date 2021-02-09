# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which holds all the methods for decrpyting the session key and generating the RSA keys
"""

import ast
import base64

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


def generateRSAKey():
    """
        Description :   Creates public and private keys using pyCrypto module
        Returns     :   Public and private keys in form of plain string (STRING)
    """
    # Generating public and private keys
    privateKey = RSA.generate(1024)
    publicKey = privateKey.publickey()
    # converting the keys to plain string
    privateKey = str(privateKey.exportKey('PEM'), 'utf-8')
    publicKey = str(publicKey.exportKey('PEM'), 'utf-8')
    return publicKey, privateKey


def decryptSessionKey(privateKey, sessionKey):
    """
        Description :   Decrypts session key using the private key
        Parameters  :   privateKey - private key to be used for decryption (STRING)
                        sessionKey - session key to be decrypted
        Returns     :   Decrypted secret key (STRING)
    """
    privateKey = RSA.importKey(privateKey.encode('utf-8'))
    decryptedSecretKey = privateKey.decrypt(ast.literal_eval(sessionKey))
    return decryptedSecretKey


def decryptCertPrivateKey(encPrivateKey, secret):
    """
        Description :   Decrypts private key using decrypted secret key
        Parameters  :   encPrivateKey - encrypted private key to be used for decryption (STRING)
                        secret - secret key to be used for decryption
        Returns     :   Decrypted private key (STRING)
    """
    privateKey = base64.b64decode(encPrivateKey.encode('utf-8'))
    cipher = AES.new(secret)
    decryptedPrivateKey = str(cipher.decrypt(base64.b64decode(privateKey)), 'utf-8').rstrip('{')
    return decryptedPrivateKey
