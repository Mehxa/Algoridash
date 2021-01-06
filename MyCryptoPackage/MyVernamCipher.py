__mydoc__ = """
----------------------------------------------------------------------------
MyVernamCipher.py, Ennaayattulla
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
alphabets = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "G": 6, "H": 7, "I": 8, "J": 9, "K": 10, "L": 11, "M": 12,
             "N": 13, "O": 14, "P": 15, "Q": 16, "R": 17, "S": 18, "T": 19, "U": 20, "V": 21, "W": 22, "X": 23, "Y": 24, "Z": 25}


def encrypt(key, plaintext):
    encrypted_text = ""
    key = key.upper()
    for i in range(len(key)):
        if plaintext[i].islower():
            plainletter = plaintext[i].upper()
            if plainletter in alphabets and key[i] in alphabets:
                new_digit = (alphabets[key[i]] + alphabets[plainletter]) % 26
                for letter in alphabets:
                    if alphabets[letter] == new_digit:
                        encrypted_text += letter.lower()
                        break
            else:
                encrypted_text += plaintext[i]
        else:
            if plaintext[i] in alphabets and key[i] in alphabets:
                new_digit = (alphabets[key[i]] + alphabets[plaintext[i]]) % 26
                for letter in alphabets:
                    if alphabets[letter] == new_digit:
                        encrypted_text += letter
                        break
            else:
                encrypted_text += plaintext[i]
    return encrypted_text


def decrypt(key, encrypted_text):
    plaintext = ""
    key = key.upper()
    for i in range(len(key)):
        if encrypted_text[i].islower():
            encrypted_letter = encrypted_text[i].upper()
            if encrypted_letter in alphabets and key[i] in alphabets:
                new_digit = (alphabets[encrypted_letter] - alphabets[key[i]]) % 26
                for letter in alphabets:
                    if alphabets[letter] == new_digit:
                        plaintext += letter.lower()
                        break
            else:
                plaintext += encrypted_text[i]
        else:
            if encrypted_text[i] in alphabets and key[i] in alphabets:
                new_digit = (alphabets[encrypted_text[i]] - alphabets[key[i]]) % 26
                for letter in alphabets:
                    if alphabets[letter] == new_digit:
                        plaintext += letter
                        break
            else:
                plaintext += encrypted_text[i]
    return plaintext




