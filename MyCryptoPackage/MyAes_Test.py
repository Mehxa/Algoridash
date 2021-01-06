__mydoc__ = """
MyAes_Test.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""


from MyCryptoPackage import MyAes


def run_test():
    print(__mydoc__)
    print(MyAes.__mydoc__)

    key = MyAes.get_random_alphanumeric(32)
    iv = MyAes.get_random_alphanumeric(16)
    plaintext_string = "Testing AES encrypt and decrypt."

    # encode plaintext, then encrypt
    ciphertext = MyAes.CBC_encrypt(key, plaintext_string.encode("utf8"), iv)

    # decrypt ciphertext, then decode
    decryptedtext_string = MyAes.CBC_decrypt(key, ciphertext, iv).decode("utf-8")

    print("CBC plaintext: " + plaintext_string)
    print("CBC ciphertext:", ciphertext)
    print("CBC decryptedtext: " + decryptedtext_string)

    ciphertext = MyAes.CFB_encrypt(key, plaintext_string.encode("utf8"), iv)

    # decrypt ciphertext, then decode
    decryptedtext_string = MyAes.CFB_decrypt(key, ciphertext, iv).decode("utf8")

    print("CFB plaintext: " + plaintext_string)
    print("CFB decryptedtext: " + decryptedtext_string)
    ciphertext = MyAes.OFB_encrypt(key, plaintext_string.encode("utf8"), iv)

    # decrypt ciphertext, then decode
    decryptedtext_string = MyAes.OFB_decrypt(key, ciphertext, iv).decode("utf8")

    print("OFB plaintext: " + plaintext_string)
    print("OFB decryptedtext: " + decryptedtext_string)
    ciphertext = MyAes.ECB_encrypt(key, plaintext_string.encode("utf8"))

    # decrypt ciphertext, then decode
    decryptedtext_string = MyAes.ECB_decrypt(key, ciphertext).decode("utf8")

    print("ECB plaintext: " + plaintext_string)
    print("ECB decryptedtext: " + decryptedtext_string)

    return


if __name__ == "__main__":
    run_test()
