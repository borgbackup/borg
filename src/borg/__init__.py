from packaging.version import parse as parse_version

from ._version import version as __version__


_v = parse_version(__version__)
__version_tuple__ = _v._version.release  # type: ignore

# assert that all semver components are integers
# this is mainly to show errors when people repackage poorly
# and setuptools_scm determines a 0.1.dev... version
assert all(isinstance(v, int) for v in __version_tuple__), (
    """\
Broken BorgBackup version metadata: %r

Version metadata is obtained dynamically during installation via setuptools_scm;
please ensure your Git repository has the correct tags, or provide the version
using SETUPTOOLS_SCM_PRETEND_VERSION in your build script.
"""
    % __version__
)
