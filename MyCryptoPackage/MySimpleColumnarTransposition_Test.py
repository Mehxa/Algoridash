__mydoc__ = """
MySimpleColumnarTransposition_Test.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""

from MyCryptoPackage import MySimpleColumnarTransposition


def run_test():
    print(__mydoc__)
    print(MySimpleColumnarTransposition.__mydoc__)

    key = "banana"

    plaintext = "watermelon"

    ciphertext = MySimpleColumnarTransposition.encrypt(key, plaintext)
    decryptedtext = MySimpleColumnarTransposition.decrypt(key, ciphertext)
    print("Plaintext:", plaintext)
    key = list(key)
    print("Key: \n", key)
    print("Plaintext:")
    row = []
    for i in range(len(plaintext)):
        if (i + 1) % len(key) != 0:
            row.append(plaintext[i])
            if i == len(plaintext) - 1:
                print(row)
        else:
            row.append(plaintext[i])
            print(row)
            row = []
    print("Ciphertext:", ciphertext)
    print("Decryptedtext:", decryptedtext)

    return


if __name__ == "__main__":
    run_test()
