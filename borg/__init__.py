from distutils.version import LooseVersion

from ._version import version as __version__


__version_tuple__ = tuple(LooseVersion(__version__).version[:3])
