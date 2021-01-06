__mydoc__ = """
MyVernamCipher_Test.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""
from MyCryptoPackage import MyVernamCipher


def run_test():
    print(__mydoc__)
    print(MyVernamCipher.__mydoc__)
    plaintext = "What EvrEven"
    key = "Huh Ag a i n"
    encrypted_text = MyVernamCipher.encrypt(key, plaintext)
    decrypted_text = MyVernamCipher.decrypt(key, encrypted_text)

    print("Plaintext:", plaintext)
    print("Encrypted Text:", encrypted_text)
    print("Decrypted Text:", decrypted_text)


if __name__ == "__main__":
    run_test()
