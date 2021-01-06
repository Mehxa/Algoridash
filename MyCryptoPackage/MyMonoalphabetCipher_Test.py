__mydoc__ = """
MyMonoalphabetCipher_Test.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""
from MyCryptoPackage import MyMonoalphabetCipher


def run_test():
    print(__mydoc__)
    print(MyMonoalphabetCipher.__mydoc__)

    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    plaintext = "On this day, I see clearly, everything has come to life"
    ciphertext = MyMonoalphabetCipher.encrpyt(key, plaintext)
    decrypted_text = MyMonoalphabetCipher.decrpyt(key, ciphertext)

    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext)
    print("Decrypted text:", decrypted_text)

if __name__ == "__main__":
    run_test()
