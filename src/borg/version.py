import re


def parse_version(version):
    """
    Simplistic parser for setuptools_scm versions.

    Supports final versions and alpha ('a'), beta ('b') and release candidate ('rc') versions.
    It does not try to parse anything else than that, even if there is more in the version string.

    Output is a version tuple containing integers. It ends with one or two elements that ensure that relational
    operators yield correct relations for alpha, beta and rc versions, too.
    For final versions the last element is a -1.
    For prerelease versions the last two elements are a smaller negative number and the number of e.g. the beta.

    This version format is part of the remote protocol, don‘t change in breaking ways.
    """
    version_re = r"""
        (?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)   # version, e.g. 1.2.33
        (?P<prerelease>(?P<ptype>a|b|rc)(?P<pnum>\d+))?  # optional prerelease, e.g. a1 or b2 or rc33
    """
    m = re.match(version_re, version, re.VERBOSE)
    if m is None:
        raise ValueError('Invalid version string %s' % version)
    gd = m.groupdict()
    version = [int(gd['major']), int(gd['minor']), int(gd['patch'])]
    if m.lastgroup == 'prerelease':
        p_type = {'a': -4, 'b': -3, 'rc': -2}[gd['ptype']]
        p_num = int(gd['pnum'])
        version += [p_type, p_num]
    else:
        version += [-1]
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
