import os
import re
from queue import LifoQueue


def translate(pat, match_end=r"\Z"):
    """Translate a shell-style pattern to a regular expression.

    The pattern may include ``**<sep>`` (<sep> stands for the platform-specific path separator; "/" on POSIX systems)
    for matching zero or more directory levels and "*" for matching zero or more arbitrary characters except any path
    separator. Wrap meta-characters in brackets for a literal match (i.e. "[?]" to match the literal character "?").

    Using match_end=regex one can give a regular expression that is used to match after the regex that is generated from
    the pattern. The default is to match the end of the string.

    This function is derived from the "fnmatch" module distributed with the Python standard library.

    :copyright: 2001-2016 Python Software Foundation. All rights reserved.
    :license: PSFLv2
    """
    pat = _translate_alternatives(pat)

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
                res += rf"(?:[^\{sep}]*\{sep})*"
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
        elif c in "(|)":
            if i > 0 and pat[i - 1] != "\\":
                res += c
        else:
            res += re.escape(c)

    return "(?ms)" + res + match_end


def _parse_braces(pat):
    """Returns the index values of paired braces in `pat` as a list of tuples.

    The dict's keys are the indexes corresponding to opening braces. Initially,
    they are set to a value of `None`. Once a corresponding closing brace is found,
    the value is updated. All dict keys with a positive int value are valid pairs.

    Cannot rely on re.match("[^\\(\\\\)*]?{.*[^\\(\\\\)*]}") because, while it
    does handle unpaired braces and nested pairs of braces, it misses sequences
    of paired braces. E.g.: "{foo,bar}{bar,baz}" would translate, incorrectly, to
    "(foo|bar\\}\\{bar|baz)" instead of, correctly, to "(foo|bar)(bar|baz)"

    So this function parses in a left-to-right fashion, tracking pairs with a LIFO
    queue: pushing opening braces on and popping them off when finding a closing
    brace.
    """
    curly_q = LifoQueue()
    pairs: dict[int, int] = dict()

    for idx, c in enumerate(pat):
        if c == "{":
            if idx == 0 or pat[idx - 1] != "\\":
                # Opening brace is not escaped.
                # Add to dict
                pairs[idx] = None
                # Add to queue
                curly_q.put(idx)
        if c == "}" and curly_q.qsize():
            # If queue is empty, then cannot close pair.
            if idx > 0 and pat[idx - 1] != "\\":
                # Closing brace is not escaped.
                # Pop off the index of the corresponding opening brace, which
                # provides the key in the dict of pairs, and set its value.
                pairs[curly_q.get()] = idx
    return [(opening, closing) for opening, closing in pairs.items() if closing is not None]


def _translate_alternatives(pat):
    """Translates the shell-style alternative portions of the pattern to regular expression groups.

    For example: {alt1,alt2} -> (alt1|alt2)
    """
    # Parse pattern for paired braces.
    brace_pairs = _parse_braces(pat)

    pat_list = list(pat)  # Convert to list in order to subscript characters.

    # Convert non-escaped commas within groups to pipes.
    # Passing, e.g. "{a\,b}.txt" to the shell expands to "{a,b}.txt", whereas
    # "{a\,,b}.txt" expands to "a,.txt" and "b.txt"
    for opening, closing in brace_pairs:
        commas = 0

        for i in range(opening + 1, closing):  # Convert non-escaped commas to pipes.
            if pat_list[i] == ",":
                if i == opening or pat_list[i - 1] != "\\":
                    pat_list[i] = "|"
                    commas += 1
            elif pat_list[i] == "|" and (i == opening or pat_list[i - 1] != "\\"):
                # Nested groups have their commas converted to pipes when traversing the parent group.
                # So in order to confirm the presence of a comma in the original, shell-style pattern,
                # we must also check for a pipe.
                commas += 1

        # Convert paired braces into parentheses, but only if at least one comma is present.
        if commas > 0:
            pat_list[opening] = "("
            pat_list[closing] = ")"

    return "".join(pat_list)
