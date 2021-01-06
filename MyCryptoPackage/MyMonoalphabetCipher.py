__mydoc__ = """
----------------------------------------------------------------------------
MyMonoalphabetCipher.py, Ennaayattulla
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

alphabets = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q",
             "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]


def encrpyt(key, plaintext):
    conversion_dict = {}
    for i in range(len(key)):
        conversion_dict[alphabets[i]] = key[i]
    ciphertext = ""
    for i in plaintext:
        if i.islower():
            i = i.upper()
            if i in alphabets:
                ciphertext += conversion_dict[i].lower()
            else:
                ciphertext += i
        else:
            if i in alphabets:
                ciphertext += conversion_dict[i]
            else:
                ciphertext += i

    return ciphertext


def decrpyt(key, ciphertext):
    conversion_dict = {}
    for i in range(len(key)):
        conversion_dict[key[i]] = alphabets[i]
    plaintext = ""
    for i in ciphertext:
        if i.islower():
            i = i.upper()
            if i in alphabets:
                plaintext += conversion_dict[i].lower()
            else:
                plaintext += i
        else:
            if i in alphabets:
                plaintext += conversion_dict[i]
            else:
                plaintext += i
    return plaintext
