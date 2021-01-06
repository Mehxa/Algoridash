__mydoc__ = """
MyModule_TestAll.py, teoyk
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""

from MyCryptoPackage import MyModule_Test
from MyCryptoPackage import MyCaesarCipher_Test
from MyCryptoPackage import MyAes_Test
from MyCryptoPackage import MyRailFence_Test
from MyCryptoPackage import MySimpleColumnarTransposition_Test
from MyCryptoPackage import MyMonoalphabetCipher_Test
from MyCryptoPackage import MyVernamCipher_Test
from MyCryptoPackage import MyDiffieHellman_Test
# from MyCryptoPackage import MyRsa_Test
# from MyCryptoPackage import MyHash_Test


def run_test():
    print(__mydoc__)

    MyModule_Test.run_test()
    MyCaesarCipher_Test.run_test()
    MyAes_Test.run_test()
    MyRailFence_Test.run_test()
    MySimpleColumnarTransposition_Test.run_test()
    MyMonoalphabetCipher_Test.run_test()
    MyVernamCipher_Test.run_test()
    MyDiffieHellman_Test.run_test()

    return


if __name__ == "__main__":
    run_test()
