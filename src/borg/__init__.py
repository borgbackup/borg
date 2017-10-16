from distutils.version import LooseVersion

# IMPORTANT keep imports from borg here to a minimum because our testsuite depends on
# beeing able to import borg.constants and then monkey patching borg.constants.PBKDF2_ITERATIONS
from ._version import version as __version__


__version_tuple__ = tuple(LooseVersion(__version__).version[:3])

# assert that all semver components are integers
# this is mainly to show errors when people repackage poorly
# and setuptools_scm determines a 0.1.dev... version
assert all(isinstance(v, int) for v in __version_tuple__), \
    """\
broken borgbackup version metadata: %r

version metadata is obtained dynamically on installation via setuptools_scm,
please ensure your git repo has the correct tags or you provide the version
using SETUPTOOLS_SCM_PRETEND_VERSION in your build script.
""" % __version__
