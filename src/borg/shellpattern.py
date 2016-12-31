import os
import re


def translate(pat):
    """Translate a shell-style pattern to a regular expression.

    The pattern may include ``**<sep>`` (<sep> stands for the platform-specific path separator; "/" on POSIX systems) for
    matching zero or more directory levels and "*" for matching zero or more arbitrary characters with the exception of
    any path separator. Wrap meta-characters in brackets for a literal match (i.e. "[?]" to match the literal character
    "?").

    This function is derived from the "fnmatch" module distributed with the Python standard library.

    Copyright (C) 2001-2017 Python Software Foundation. All rights reserved.

    TODO: support {alt1,alt2} shell-style alternatives

    """
    sep = os.path.sep
    n = len(pat)
    i = 0
    res = ""

    while i < n:
        c = pat[i]
        i += 1

        if c == "*":
            if i + 1 < n and pat[i] == "*" and pat[i + 1] == sep:
                # **/ == wildcard for 0+ full (relative) directory names with trailing slashes; the forward slash stands
                # for the platform-specific path separator
                res += r"(?:[^\%s]*\%s)*" % (sep, sep)
                i += 2
            else:
                # * == wildcard for name parts (does not cross path separator)
                res += r"[^\%s]*" % sep
        elif c == "?":
            # ? == any single character excluding path separator
            res += r"[^\%s]" % sep
        elif c == "[":
            j = i
            if j < n and pat[j] == "!":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 1
            if j >= n:
                res += "\\["
            else:
                stuff = pat[i:j].replace("\\", "\\\\")
                i = j + 1
                if stuff[0] == "!":
                    stuff = "^" + stuff[1:]
                elif stuff[0] == "^":
                    stuff = "\\" + stuff
                res += "[%s]" % stuff
        else:
            res += re.escape(c)

    return res + r"\Z(?ms)"
