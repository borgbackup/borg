import re


def parse_version(version):
    """
    simplistic parser for setuptools_scm versions

    supports final versions and alpha ('a'), beta ('b') and rc versions. It just discards commits since last tag
    and git revision hash.

    Output is a version tuple containing integers. It ends with one or two elements that ensure that relational
    operators yield correct relations for alpha, beta and rc versions too. For final versions the last element
    is a -1, for prerelease versions the last two elements are a smaller negative number and the number of e.g.
    the beta.

    Note, this sorts version 1.0 before 1.0.0.

    This version format is part of the remote protocol, don‘t change in breaking ways.
    """

    parts = version.split('+')[0].split('.')
    if parts[-1].startswith('dev'):
        del parts[-1]
    version = [int(segment) for segment in parts[:-1]]

    prerelease = re.fullmatch('([0-9]+)(a|b|rc)([0-9]+)', parts[-1])
    if prerelease:
        version_type = {'a': -4, 'b': -3, 'rc': -2}[prerelease.group(2)]
        version += [int(prerelease.group(1)), version_type, int(prerelease.group(3))]
    else:
        version += [int(parts[-1]), -1]

    return tuple(version)


def format_version(version):
    """a reverse for parse_version (obviously without the dropped information)"""
    f = []
    it = iter(version)
    while True:
        part = next(it)
        if part >= 0:
            f += str(part)
        elif part == -1:
            break
        else:
            f[-1] = f[-1] + {-2: 'rc', -3: 'b', -4: 'a'}[part] + str(next(it))
            break
    return '.'.join(f)
