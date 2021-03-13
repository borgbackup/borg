#!/usr/bin/env python3

from textwrap import indent

import borg.archiver  # noqa: F401 - need import to get Error and ErrorWithTraceback subclasses.
from borg.helpers import Error, ErrorWithTraceback

classes = Error.__subclasses__() + ErrorWithTraceback.__subclasses__()

for cls in sorted(classes, key=lambda cls: (cls.__module__, cls.__qualname__)):
    if cls is ErrorWithTraceback:
        continue
    print('   ', cls.__qualname__)
    print(indent(cls.__doc__, ' ' * 8))
