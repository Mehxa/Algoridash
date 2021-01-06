__mydoc__ = """
MyDiffieHellman_Test.py, Ennaayattulla
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""
from MyCryptoPackage import MyDiffieHellman


def run_test():
    print(__mydoc__)
    print(MyDiffieHellman.__mydoc__)
    print(MyDiffieHellman.get_keys(11, 7, 3, 6))


if __name__ == "__main__":
    run_test()
