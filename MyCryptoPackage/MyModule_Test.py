__mydoc__ = """
MyModule_Test.py, teoyk
Tested with PyCharm Community Edition 2019.3 x64, python 3.7
"""

from MyCryptoPackage import MyModule


def run_test():
    print(__mydoc__)
    print(MyModule.__mydoc__)

    print("MyModule_Test.py: run_test() is called.")
    MyModule.my_method()

    return


if __name__ == "__main__":
    run_test()
