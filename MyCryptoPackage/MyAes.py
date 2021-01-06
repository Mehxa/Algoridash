__mydoc__ = """
----------------------------------------------------------------------------
MyAes.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7

Q1. Implement get_fixed_key() to return a 256-bit AES key.

Q2. Implement get_random_key() to return a random 256-bit AES key.

Q3. Implement AES encrypt(key, plaintext_utf8, ciphertext_file) where:
- key: AES key
- plaintext_utf8: plaintext in UTF8 format
- ciphertext_file: file name of binary file to store the ciphertext
- return: nil
- assumption: use CBC mode, IV and default padding (PKCS7)

Q4. Implement AES decrypt(key, ciphertext_file) where:
- key: AES key
- ciphertext_file: name of binary file containing the ciphertext
- return: decrypted text in UTF8
- assumption: use CBC mode, IV and default padding (PKCS7)

----------------------------------------------------------------------------
"""


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import random


def get_fixed_key():
    # use fixed AES key, 256 bits
    #return b"..."
    return b'abcdefghijklmnopqrstuvwxyz123456'


def get_random_key(byte_size):
    """ generate random AES key, keysize = 32*8 = 256 bits"""
    #return get_random_bytes(...)
    return get_random_bytes(byte_size)


def get_random_alphanumeric(Size):
        allchars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        return ''.join((random.choice(allchars) for i in range(int(Size))))


def get_random_iv():
    return get_random_bytes(16)


# AES encrypt using CBC and IV, with default padding (PKCS7)
def CBC_encrypt(key, plaintext_utf8, iv):
        key = bytes(key, "utf-8")
        iv = bytes(iv, "utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext_utf8, AES.block_size))
        ciphertext = b64encode(ciphertext)
        return ciphertext


def CBC_decrypt(key, plaintext_utf8, iv):
        key = bytes(key, "utf-8")
        iv = bytes(iv, "utf-8")
        plaintext_utf8 = b64decode(plaintext_utf8)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(plaintext_utf8), AES.block_size)
        return plaintext


def CFB_encrypt(key, plaintext_utf8, iv):
        key = bytes(key, "utf-8")
        iv = bytes(iv, "utf-8")
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(pad(plaintext_utf8, AES.block_size))
        ciphertext = b64encode(ciphertext)
        return ciphertext


def CFB_decrypt(key, plaintext_utf8, iv):
        key = bytes(key, "utf-8")
        iv = bytes(iv, "utf-8")
        plaintext_utf8 = b64decode(plaintext_utf8)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = unpad(cipher.decrypt(plaintext_utf8), AES.block_size)
        return plaintext


def OFB_encrypt(key, plaintext_utf8, iv):
        key = bytes(key, "utf-8")
        iv = bytes(iv, "utf-8")
        cipher = AES.new(key, AES.MODE_OFB, iv)
        ciphertext = cipher.encrypt(pad(plaintext_utf8, AES.block_size))
        ciphertext = b64encode(ciphertext)
        return ciphertext


def OFB_decrypt(key, plaintext_utf8, iv):
        key = bytes(key, "utf-8")
        iv = bytes(iv, "utf-8")
        plaintext_utf8 = b64decode(plaintext_utf8)
        cipher = AES.new(key, AES.MODE_OFB, iv)
        plaintext = unpad(cipher.decrypt(plaintext_utf8), AES.block_size)
        return plaintext


def ECB_encrypt(key, plaintext_utf8):
        key = bytes(key, "utf-8")
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext_utf8, AES.block_size))
        ciphertext = b64encode(ciphertext)
        return ciphertext


def ECB_decrypt(key, plaintext_utf8):
        key = bytes(key, "utf-8")
        plaintext_utf8 = b64decode(plaintext_utf8)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(plaintext_utf8), AES.block_size)
        return plaintext
