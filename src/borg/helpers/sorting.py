"""
Multi-field, direction-aware, stable sorting of command output.

Used by commands offering a ``--sort-by SPEC`` option that sorts archive contents
(``borg list``, ``borg diff``), where SPEC is a comma-separated list of field names,
each optionally prefixed with "<" (ascending, the default) or ">" (descending).

Not to be confused with helpers.parseformat.SortBySpec, which is the simpler
archive-level sort spec of ``borg repo-list`` (no direction prefixes).
"""

from .argparsing import ArgumentTypeError

ASCENDING, DESCENDING = "<", ">"


def parse_sort_spec(spec):
    """Split SPEC into [(field, descending), ...]. None / empty / blank gives []."""
    result = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if part[0] in (ASCENDING, DESCENDING):
            result.append((part[1:], part[0] == DESCENDING))
        else:
            result.append((part, False))
    return result


def sort_spec_validator(allowed_keys, *, name="sort_spec"):
    """Build an argparse type= callable validating a --sort-by SPEC.

    The returned function has the allowed keys as .sort_keys, so shell completion
    can be generated from it, see archiver/completion_cmd.py.
    """
    allowed = tuple(allowed_keys)

    def validator(text):
        parsed = parse_sort_spec(text)
        if not parsed:
            raise ArgumentTypeError("unsupported sort field: empty spec")
        for field, _ in parsed:
            if field not in allowed:
                raise ArgumentTypeError(f"unsupported sort field: {field}, supported: {', '.join(allowed)}")
        return ",".join((DESCENDING if descending else "") + field for field, descending in parsed)

    validator.__name__ = name
    validator.sort_keys = allowed
    return validator


def sorted_by_spec(seq, spec, key_for):
    """Sort seq as requested by spec, using key_for(field, element) to compute sort keys.

    Sorting is stable and applied from the last field of the spec to the first, so the
    first field is the primary sort criterion.

    If spec does not select any field, seq is returned as is (and not consumed), so
    callers can keep streaming.
    """
    parsed = parse_sort_spec(spec)
    if not parsed:
        return seq
    result = list(seq)
    for field, descending in reversed(parsed):
        result.sort(key=lambda element, field=field: key_for(field, element), reverse=descending)
    return result
