# ***************************************************
# Copyright © 2020 VMware, Inc. All rights reserved.
# ***************************************************

"""
Description: Module which holds all the methods for encrypting and decrypting passwords
"""

import base64
import secrets
import string
import cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class PasswordUtilities():
    def generateMasterKey(self, length=30):
        """
            Description :   Generates a random master key of random length for creation of encryption key
            Parameters  :   length    -   Length of the master key to be generated (INTEGER)
            Returns     :   Master key
        """
        randomGenerator = secrets.SystemRandom()
        masterKey = ''.join(randomGenerator.choices(string.digits + string.ascii_letters + string.punctuation, k=length))
        return masterKey

    def readPassFile(self, fileName, v2tpassfile=False):
        """
            Description :   Read the encrypted passwords and master key from file
            Parameters: fileName to be read
            Returns     :   List of the encrypted passwords
        """
        with open(fileName, 'r') as f:
            passList = f.read().split('\n')
            # passfile holds 4 values encrypted - 1. master key, 2. vcd password, 3. nsx-t password, 4. vcenter password, 5. nsx-v password

            if v2tpassfile and len(passList) != 2:
                raise Exception("Invalid password file")

            if not v2tpassfile and len(passList) != 5:
                raise Exception("Invalid password file")
            return passList

    def writePassFile(self, data, fileName):
        """
            Description :   Write the encrypted passwords and master key to file
            Parameters  :   data    -   passwords and master key to be stored in file (STRING)
                            fileName - File path to write data
        """
        # Write file.
        with open(fileName, 'w') as f:
            f.write(data)

    def generateKey(self, masterKey):
        """
            Description :   Generates a encryption key for password encryption
            Parameters  :   masterKey    -   Master key to be used for the generation of encryption key (STRING)
            Returns     :   Encryption key
        """
        # Splitting the master key into password and encryption salt
        password = masterKey[:len(masterKey)//2].encode()
        salt = masterKey[len(masterKey)//2:].encode()
        # Creating a key derive function that would be further used for encryption key generation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=234567,
            backend=default_backend()
        )
        # Generating the encryption key
        key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
        return key

    def encrpyt(self, key, password):
        """
            Description :   Encrypts the provided password with the key provided
            Parameters  :   key       -   Encryption key to be used for encryption (BYTE-STRING)
                            password  -   Password to be encrypted (STRING)
            Returns     :   Encrypted password
        """
        try:
            f = Fernet(key)
            encrypted = f.encrypt(password.encode())
            return encrypted
        except:
            raise

    def decrypt(self, key, encryptedPassword):
        """
            Description :   Decrypts the provided password with the key provided
            Parameters  :   key                -   Encryption key to be used for decryption (BYTE-STRING)
                            encryptedPassword  -   Password to be Decrypted (STRING)
            Returns     :   Decrypted password
        """
        try:
            f = Fernet(key)
            decrypted = f.decrypt(encryptedPassword, ttl=None).decode()
            return decrypted
        except cryptography.fernet.InvalidToken:
            return str()
        except:
            raise
