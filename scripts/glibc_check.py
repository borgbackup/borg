#!/usr/bin/env python3
"""
Check whether all given binaries work with the specified glibc version.

Usage: glibc_check.py 2.11 BIN [BIN ...]

Exit code 0 means "yes"; exit code 1 means "no".
"""

import re
import subprocess
import sys

verbose = True
glibc_re = re.compile(r"GLIBC_([0-9]\.[0-9]+)")


def parse_version(v):
    major, minor = v.split(".")
    return int(major), int(minor)


def format_version(version):
    return "%d.%d" % version


def main():
    given = parse_version(sys.argv[1])
    filenames = sys.argv[2:]

    overall_versions = set()
    for filename in filenames:
        try:
            output = subprocess.check_output(["objdump", "-T", filename], stderr=subprocess.STDOUT)
            output = output.decode()
            versions = {parse_version(match.group(1)) for match in glibc_re.finditer(output)}
            requires_glibc = max(versions)
            overall_versions.add(requires_glibc)
            if verbose:
                print(f"{filename} {format_version(requires_glibc)}")
        except subprocess.CalledProcessError:
            if verbose:
                print("%s failed." % filename)

    wanted = max(overall_versions)
    ok = given >= wanted

    if verbose:
        if ok:
            print("The binaries work with the given glibc %s." % format_version(given))
        else:
            print(
                "The binaries do not work with the given glibc %s. "
                "Minimum required is %s." % (format_version(given), format_version(wanted))
            )
    return ok


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
