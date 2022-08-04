"""
dummy package init file to suppress this weird setuptools warning:

$ pip install -v .  # note: does not happen with -ve .

############################
# Package would be ignored #
############################
Python recognizes 'borg.cache_sync' as an importable package,
but it is not listed in the `packages` configuration of setuptools.

'borg.cache_sync' has been automatically added to the distribution only
because it may contain data files, but this behavior is likely to change
in future versions of setuptools (and therefore is considered deprecated).

Please make sure that 'borg.cache_sync' is included as a package by using
the `packages` configuration field or the proper discovery methods
(for example by using `find_namespace_packages(...)`/`find_namespace:`
instead of `find_packages(...)`/`find:`).

You can read more about "package discovery" and "data files" on setuptools
documentation page.
"""
