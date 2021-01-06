__mydoc__ = """
----------------------------------------------------------------------------
MyCaesarCipher.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7

MyCaesarCipher specifications:
------------------------------

encrypt(key, plaintext_utf8) where:
- key: Caesar key, e.g. 3 denotes shifting 3 character positions
- plaintext_utf8: plaintext in UTF8 format
- return: ciphertext in UTF8 format

decrypt(key, ciphertext_utf8) where:
- key: Caesar key, e.g. 3 denotes shifting 3 character positions
- ciphertext_utf8: ciphertext in UTF8 format
- return: decrypted text in UTF8 format

Use/modify MyCaesarCipher_Test.py to test your implementations.

Questions:
----------

Q1. Implement encrypt() and decrypt() to handle only upper case, 
so that you get the following plaintexts and corresponding ciphertexts:

plaintext: HELLO
ciphertext: KHOOR
decryptedtext: HELLO

plaintext: Hello!
ciphertext: Kello!
decryptedtext: Hello!

Q2. Enhance encrypt() and decrypt() to handle both upper and lower cases, 
so that you get the following plaintexts and corresponding ciphertexts:

plaintext: HELLO
ciphertext: KHOOR
decryptedtext: HELLO

plaintext: Hello!
ciphertext: Khoor!
decryptedtext: Hello!

Q3. Enhance encrypt() and decrypt() to handle all base64 characters, 
so that you get the following plaintexts and corresponding ciphertexts:

plaintext: Hello123+/=
ciphertext: Khoor456ABC
decryptedtext: Hello123+/=
----------------------------------------------------------------------------

"""


LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='    # Q1, Q2, Q3


def encrypt(key, plaintext_utf8):
    ciphertext_utf8 = ""

    for character in plaintext_utf8:
        if character in LETTERS:
            position = LETTERS.find(character)
            position += key
            # get the character position
            #position = ... # hint: use find()
            #position = position + ...

            # wrap-around if position >= length of LETTERS
            #if position >= len(LETTERS):
                #position = position - ...
            if position >= len(LETTERS):
                position -= len(LETTERS)
            # append encrypted character
            #ciphertext_utf8 = ciphertext_utf8 + ...
            ciphertext_utf8 += LETTERS[position]

        else:
            # append character without encrypting
            #ciphertext_utf8 = ciphertext_utf8 + ...
            ciphertext_utf8 += character

    return ciphertext_utf8


def decrypt(key, ciphertext_utf8):
    decryptedtext_utf = ""

    for character in ciphertext_utf8:
        if character in LETTERS:
            position = LETTERS.find(character)
            position -= key
            # get the character position
            #position = ... # hint: use find()
            #position = position - ...

            # wrap-around if position >= length of LETTERS
            #if position < 0:
                #position = position + ...
            if position < 0:
                position += len(LETTERS)

            # append encrypted character
            #decryptedtext_utf = decryptedtext_utf + ...
            decryptedtext_utf += LETTERS[position]

        else:
            # append character without encrypting
            #decryptedtext_utf = decryptedtext_utf + ...
            decryptedtext_utf += character

    return decryptedtext_utf
