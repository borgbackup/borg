#!/usr/bin/env python3
# this script automatically generates the error list for the docs by
# looking at the "Error" class and its subclasses.

from textwrap import indent

import borg.archiver  # noqa: F401 - need import to get Error subclasses.
from borg.constants import *  # NOQA
from borg.helpers import Error, BackupError, BorgWarning


def subclasses(cls):
    direct_subclasses = cls.__subclasses__()
    return set(direct_subclasses) | {s for c in direct_subclasses for s in subclasses(c)}


# 0, 1, 2 are used for success, generic warning, generic error
# 3..99 are available for specific errors
# 100..127 are available for specific warnings
# 128+ are reserved for signals
free_error_rcs = set(range(EXIT_ERROR_BASE, EXIT_WARNING_BASE))  # 3 .. 99
free_warning_rcs = set(range(EXIT_WARNING_BASE, EXIT_SIGNAL_BASE))  # 100 .. 127

# these classes map to rc 2
generic_error_rc_classes = set()
generic_warning_rc_classes = set()

error_classes = {Error} | subclasses(Error)

for cls in sorted(error_classes, key=lambda cls: (cls.__module__, cls.__qualname__)):
    traceback = "yes" if cls.traceback else "no"
    rc = cls.exit_mcode
    print("   ", cls.__qualname__, "rc:", rc, "traceback:", traceback)
    print(indent(cls.__doc__, " " * 8))
    if rc in free_error_rcs:
        free_error_rcs.remove(rc)
    elif rc == 2:
        generic_error_rc_classes.add(cls.__qualname__)
    else:  # rc != 2
        # if we did not intentionally map this to the generic error rc, this might be an issue:
        print(f"ERROR: {rc} is not a free/available RC, but either duplicate or invalid")

print()
print("free error RCs:", sorted(free_error_rcs))
print("generic errors:", sorted(generic_error_rc_classes))

warning_classes = {BorgWarning} | subclasses(BorgWarning) | {BackupError} | subclasses(BackupError)

for cls in sorted(warning_classes, key=lambda cls: (cls.__module__, cls.__qualname__)):
    rc = cls.exit_mcode
    print("   ", cls.__qualname__, "rc:", rc)
    print(indent(cls.__doc__, " " * 8))
    if rc in free_warning_rcs:
        free_warning_rcs.remove(rc)
    elif rc == 1:
        generic_warning_rc_classes.add(cls.__qualname__)
    else:  # rc != 1
        # if we did not intentionally map this to the generic warning rc, this might be an issue:
        print(f"ERROR: {rc} is not a free/available RC, but either duplicate or invalid")

print("\n")
print("free warning RCs:", sorted(free_warning_rcs))
print("generic warnings:", sorted(generic_warning_rc_classes))
