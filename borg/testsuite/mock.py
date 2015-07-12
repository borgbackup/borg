"""
Mocking

Note: unittest.mock is broken on at least python 3.3.6 and 3.4.0.
      it silently ignores mistyped method names starting with assert_...,
      does nothing and just succeeds.
      The issue was fixed in the separately distributed "mock" lib, you
      get an AttributeError there. So, always use that one!

Details:

http://engineeringblog.yelp.com/2015/02/assert_called_once-threat-or-menace.html
"""
from mock import *
