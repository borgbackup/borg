import re

from ._version import version as __version__

version_re = r'(\d+)\.(\d+)\.(\d+)'

m = re.match(version_re, __version__)
if m:
    __version_tuple__ = tuple(map(int, m.groups()))
else:
    raise RuntimeError("Can't parse __version__: %r" % __version__)
