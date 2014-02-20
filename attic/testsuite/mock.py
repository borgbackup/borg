try:
    # Only available in python 3.3+
    from unittest.mock import *
except ImportError:
    from mock import *
