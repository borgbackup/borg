import pytest

from ...helpers.argparsing import ArgumentTypeError
from ...helpers.sorting import parse_sort_spec, sort_spec_validator, sorted_by_spec


@pytest.mark.parametrize(
    "spec, expected",
    [
        (None, []),
        ("", []),
        ("   ", []),
        (",", []),
        ("path", [("path", False)]),
        ("<path", [("path", False)]),
        (">path", [("path", True)]),
        (" >size , path ", [("size", True), ("path", False)]),
        ("size,,path", [("size", False), ("path", False)]),
    ],
)
def test_parse_sort_spec(spec, expected):
    assert parse_sort_spec(spec) == expected


def test_validator_accepts_and_normalizes():
    validator = sort_spec_validator(("path", "size"))
    assert validator("path") == "path"
    assert validator("<path") == "path"  # "<" is the default and thus dropped
    assert validator(" >size , path ") == ">size,path"


def test_validator_rejects():
    validator = sort_spec_validator(("path", "size"))
    for spec in ("", "  ", ",", "nosuchfield", "path,nosuchfield", ">", "<"):
        with pytest.raises(ArgumentTypeError):
            validator(spec)


def test_validator_has_sort_keys():
    validator = sort_spec_validator(["path", "size"], name="test_sort_spec")
    assert validator.sort_keys == ("path", "size")
    assert validator.__name__ == "test_sort_spec"


def key_for(field, element):
    return element[field]


def test_sorted_by_spec_keeps_unsorted_seq_as_is():
    # important: without a sort spec, callers shall be able to keep streaming
    seq = iter([{"path": "b"}, {"path": "a"}])
    assert sorted_by_spec(seq, None, key_for) is seq
    assert sorted_by_spec(seq, "", key_for) is seq


def test_sorted_by_spec_single_field():
    seq = [{"path": "b"}, {"path": "c"}, {"path": "a"}]
    assert [e["path"] for e in sorted_by_spec(seq, "path", key_for)] == ["a", "b", "c"]
    assert [e["path"] for e in sorted_by_spec(seq, ">path", key_for)] == ["c", "b", "a"]


def test_sorted_by_spec_multiple_fields():
    seq = [{"size": 1, "path": "b"}, {"size": 2, "path": "c"}, {"size": 1, "path": "a"}, {"size": 2, "path": "a"}]
    # first field is the primary criterion, following fields break ties
    result = [(e["size"], e["path"]) for e in sorted_by_spec(seq, ">size,path", key_for)]
    assert result == [(2, "a"), (2, "c"), (1, "a"), (1, "b")]
    result = [(e["size"], e["path"]) for e in sorted_by_spec(seq, "size,>path", key_for)]
    assert result == [(1, "b"), (1, "a"), (2, "c"), (2, "a")]


def test_sorted_by_spec_is_stable():
    # equal sort keys must not change the relative order of the elements
    seq = [{"size": 1, "path": "b"}, {"size": 1, "path": "a"}, {"size": 1, "path": "c"}]
    assert [e["path"] for e in sorted_by_spec(seq, "size", key_for)] == ["b", "a", "c"]
