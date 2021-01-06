__mydoc__ = """
MyCaesarCipher_Test.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""

from MyCryptoPackage import MyCaesarCipher


def run_test():
    print(__mydoc__)
    print(MyCaesarCipher.__mydoc__)

    key = 3

    plaintext = "HELLO"     # Q1, Q2
    ciphertext = MyCaesarCipher.encrypt(key, plaintext)
    decryptedtext = MyCaesarCipher.decrypt(key, ciphertext)
    print("plaintext: " + plaintext)
    print("ciphertext: " + ciphertext)
    print("decryptedtext: " + decryptedtext + "\n")

    plaintext = "Hello!"    # Q1, Q2
    ciphertext = MyCaesarCipher.encrypt(key, plaintext)
    decryptedtext = MyCaesarCipher.decrypt(key, ciphertext)
    print("plaintext: " + plaintext)
    print("ciphertext: " + ciphertext)
    print("decryptedtext: " + decryptedtext + "\n")

    plaintext = "Hello123+/="   # Q3
    ciphertext = MyCaesarCipher.encrypt(key, plaintext)
    decryptedtext = MyCaesarCipher.decrypt(key, ciphertext)
    print("plaintext: " + plaintext)
    print("ciphertext: " + ciphertext)
    print("decryptedtext: " + decryptedtext + "\n")

    return


if __name__ == "__main__":
    run_test()
