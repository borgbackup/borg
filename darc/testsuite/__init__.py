import unittest


class DarcTestCase(unittest.TestCase):
    """
    """
    assert_equal = unittest.TestCase.assertEqual
    assert_not_equal = unittest.TestCase.assertNotEqual
    assert_raises = unittest.TestCase.assertRaises


def get_tests(suite):
    """Generates a sequence of tests from a test suite
    """
    for item in suite:
        try:
            # TODO: This could be "yield from..." with Python 3.3+ 
            for i in get_tests(item):
                yield i
        except TypeError:
            yield item


class TestLoader(unittest.TestLoader):
    """A customzied test loader that properly detects and filters our test cases
    """
    def loadTestsFromName(self, pattern, module=None):
        suite = self.discover('darc.testsuite', '*.py')
        tests = unittest.TestSuite()
        for test in get_tests(suite):
            if pattern.lower() in test.id().lower():
                tests.addTest(test)
        return tests


