__mydoc__ = """
----------------------------------------------------------------------------
MyDiffieHellman.py, Ennaayattulla
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


def get_keys(n, g, x, y):
    A = g**x % n
    B = g**y % n
    K1 = B**x % n
    K2 = A**y % n
    return [K1, K2]

