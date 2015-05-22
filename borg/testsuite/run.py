import unittest

from . import TestLoader


def main():
    unittest.main(testLoader=TestLoader(), defaultTest='')


if __name__ == '__main__':
    main()
