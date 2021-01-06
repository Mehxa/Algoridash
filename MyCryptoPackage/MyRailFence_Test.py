__mydoc__ = """
MyRailFence_Test.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""

from MyCryptoPackage import MyRailFence


def run_test():
    print(__mydoc__)
    print(MyRailFence.__mydoc__)

    rows = 9

    plaintext = "AbC dEf GhI jKlM"

    ciphertext = MyRailFence.encrypt(rows, plaintext)
    decryptedtext = MyRailFence.decrypt(rows, ciphertext)
    print("Plaintext:", plaintext)
    print("Ciphertext", ciphertext)
    print("Decryptedtext", decryptedtext)

    return
