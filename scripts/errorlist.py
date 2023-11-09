#!/usr/bin/env python3
# this script automatically generates the error list for the docs by
# looking at the "Error" class and its subclasses.

from textwrap import indent

import borg.archiver  # noqa: F401 - need import to get Error subclasses.
from borg.helpers import Error


def subclasses(cls):
    direct_subclasses = cls.__subclasses__()
    return set(direct_subclasses).union([s for c in direct_subclasses for s in subclasses(c)])


# 0, 1, 2 are used for success, generic warning, generic error
# 3..99 are available for specific errors
# 100..127 are available for specific warnings
# 128+ are reserved for signals
free_rcs = set(range(3, 99+1))  # 3 .. 99 (we only deal with errors here)

# these classes map to rc 2
generic_rc_classes = set()

classes = {Error}.union(subclasses(Error))

for cls in sorted(classes, key=lambda cls: (cls.__module__, cls.__qualname__)):
    traceback = "yes" if cls.traceback else "no"
    rc = cls.exit_mcode
    print('   ', cls.__qualname__, 'rc:', rc, 'traceback:', traceback)
    print(indent(cls.__doc__, ' ' * 8))
    if rc in free_rcs:
        free_rcs.remove(rc)
    elif rc == 2:
        generic_rc_classes.add(cls.__qualname__)
    else:  # rc != 2
        # if we did not intentionally map this to the generic error rc, this might be an issue:
        print(f'ERROR: {rc} is not a free/available RC, but either duplicate or invalid')

print()
print('free RCs:', sorted(free_rcs))
print('generic errors:', sorted(generic_rc_classes))
