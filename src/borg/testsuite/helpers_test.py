from argparse import ArgumentTypeError
from datetime import datetime, timezone
from io import StringIO, BytesIO

import pytest

from ..archiver.prune_cmd import prune_split
from ..constants import *  # NOQA
from ..helpers import ChunkIteratorFileWrapper, ChunkerParams
from ..helpers import chunkit
from ..helpers import iter_separated
from ..helpers import classify_ec, max_ec


@pytest.mark.parametrize(
    "chunker_params, expected_return",
    [
        ("default", ("buzhash", 19, 23, 21, 4095)),
        ("19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("buzhash,19,23,21,4095", ("buzhash", 19, 23, 21, 4095)),
        ("10,23,16,4095", ("buzhash", 10, 23, 16, 4095)),
        ("fixed,4096", ("fixed", 4096, 0)),
        ("fixed,4096,200", ("fixed", 4096, 200)),
    ],
)
def test_valid_chunkerparams(chunker_params, expected_return):
    assert ChunkerParams(chunker_params) == expected_return


@pytest.mark.parametrize(
    "invalid_chunker_params",
    [
        "crap,1,2,3,4",  # invalid algo
        "buzhash,5,7,6,4095",  # too small min. size
        "buzhash,19,24,21,4095",  # too big max. size
        "buzhash,23,19,21,4095",  # violates min <= mask <= max
        "fixed,63",  # too small block size
        "fixed,%d,%d" % (MAX_DATA_SIZE + 1, 4096),  # too big block size
        "fixed,%d,%d" % (4096, MAX_DATA_SIZE + 1),  # too big header size
    ],
)
def test_invalid_chunkerparams(invalid_chunker_params):
    with pytest.raises(ArgumentTypeError):
        ChunkerParams(invalid_chunker_params)


class MockArchive:
    def __init__(self, ts, id):
        self.ts = ts
        self.id = id

    def __repr__(self):
        return f"{self.id}: {self.ts.isoformat()}"


# This is the local timezone of the system running the tests.
# We need this e.g. to construct archive timestamps for the prune tests,
# because borg prune operates in the local timezone (it first converts the
# archive timestamp to the local timezone). So, if we want the y/m/d/h/m/s
# values which prune uses to be exactly the ones we give [and NOT shift them
# by tzoffset], we need to give the timestamps in the same local timezone.
# Please note that the timestamps in a real borg archive or manifest are
# stored in UTC timezone.
local_tz = datetime.now(tz=timezone.utc).astimezone(tz=None).tzinfo


@pytest.mark.parametrize(
    "rule,num_to_keep,expected_ids",
    [
        ("yearly", 3, (13, 2, 1)),
        ("monthly", 3, (13, 8, 4)),
        ("weekly", 2, (13, 8)),
        ("daily", 3, (13, 8, 7)),
        ("hourly", 3, (13, 10, 8)),
        ("minutely", 3, (13, 10, 9)),
        ("secondly", 4, (13, 12, 11, 10)),
        ("daily", 0, []),
    ],
)
def test_prune_split(rule, num_to_keep, expected_ids):
    def subset(lst, ids):
        return {i for i in lst if i.id in ids}

    archives = [
        # years apart
        MockArchive(datetime(2015, 1, 1, 10, 0, 0, tzinfo=local_tz), 1),
        MockArchive(datetime(2016, 1, 1, 10, 0, 0, tzinfo=local_tz), 2),
        MockArchive(datetime(2017, 1, 1, 10, 0, 0, tzinfo=local_tz), 3),
        # months apart
        MockArchive(datetime(2017, 2, 1, 10, 0, 0, tzinfo=local_tz), 4),
        MockArchive(datetime(2017, 3, 1, 10, 0, 0, tzinfo=local_tz), 5),
        # days apart
        MockArchive(datetime(2017, 3, 2, 10, 0, 0, tzinfo=local_tz), 6),
        MockArchive(datetime(2017, 3, 3, 10, 0, 0, tzinfo=local_tz), 7),
        MockArchive(datetime(2017, 3, 4, 10, 0, 0, tzinfo=local_tz), 8),
        # minutes apart
        MockArchive(datetime(2017, 10, 1, 9, 45, 0, tzinfo=local_tz), 9),
        MockArchive(datetime(2017, 10, 1, 9, 55, 0, tzinfo=local_tz), 10),
        # seconds apart
        MockArchive(datetime(2017, 10, 1, 10, 0, 1, tzinfo=local_tz), 11),
        MockArchive(datetime(2017, 10, 1, 10, 0, 3, tzinfo=local_tz), 12),
        MockArchive(datetime(2017, 10, 1, 10, 0, 5, tzinfo=local_tz), 13),
    ]
    kept_because = {}
    keep = prune_split(archives, rule, num_to_keep, kept_because)

    assert set(keep) == subset(archives, expected_ids)
    for item in keep:
        assert kept_because[item.id][0] == rule


def test_prune_split_keep_oldest():
    def subset(lst, ids):
        return {i for i in lst if i.id in ids}

    archives = [
        # oldest backup, but not last in its year
        MockArchive(datetime(2018, 1, 1, 10, 0, 0, tzinfo=local_tz), 1),
        # an interim backup
        MockArchive(datetime(2018, 12, 30, 10, 0, 0, tzinfo=local_tz), 2),
        # year-end backups
        MockArchive(datetime(2018, 12, 31, 10, 0, 0, tzinfo=local_tz), 3),
        MockArchive(datetime(2019, 12, 31, 10, 0, 0, tzinfo=local_tz), 4),
    ]

    # Keep oldest when retention target can't otherwise be met
    kept_because = {}
    keep = prune_split(archives, "yearly", 3, kept_because)

    assert set(keep) == subset(archives, [1, 3, 4])
    assert kept_because[1][0] == "yearly[oldest]"
    assert kept_because[3][0] == "yearly"
    assert kept_because[4][0] == "yearly"

    # Otherwise, prune it
    kept_because = {}
    keep = prune_split(archives, "yearly", 2, kept_because)

    assert set(keep) == subset(archives, [3, 4])
    assert kept_because[3][0] == "yearly"
    assert kept_because[4][0] == "yearly"


def test_prune_split_no_archives():
    archives = []

    kept_because = {}
    keep = prune_split(archives, "yearly", 3, kept_because)

    assert keep == []
    assert kept_because == {}


def test_chunk_file_wrapper():
    cfw = ChunkIteratorFileWrapper(iter([b"abc", b"def"]))
    assert cfw.read(2) == b"ab"
    assert cfw.read(50) == b"cdef"
    assert cfw.exhausted

    cfw = ChunkIteratorFileWrapper(iter([]))
    assert cfw.read(2) == b""
    assert cfw.exhausted


def test_chunkit():
    it = chunkit("abcdefg", 3)
    assert next(it) == ["a", "b", "c"]
    assert next(it) == ["d", "e", "f"]
    assert next(it) == ["g"]
    with pytest.raises(StopIteration):
        next(it)
    with pytest.raises(StopIteration):
        next(it)

    it = chunkit("ab", 3)
    assert list(it) == [["a", "b"]]

    it = chunkit("", 3)
    assert list(it) == []


def test_iter_separated():
    # newline and utf-8
    sep, items = "\n", ["foo", "bar/baz", "αáčő"]
    fd = StringIO(sep.join(items))
    assert list(iter_separated(fd)) == items
    # null and bogus ending
    sep, items = "\0", ["foo/bar", "baz", "spam"]
    fd = StringIO(sep.join(items) + "\0")
    assert list(iter_separated(fd, sep=sep)) == ["foo/bar", "baz", "spam"]
    # multichar
    sep, items = "SEP", ["foo/bar", "baz", "spam"]
    fd = StringIO(sep.join(items))
    assert list(iter_separated(fd, sep=sep)) == items
    # bytes
    sep, items = b"\n", [b"foo", b"blop\t", b"gr\xe4ezi"]
    fd = BytesIO(sep.join(items))
    assert list(iter_separated(fd)) == items


@pytest.mark.parametrize(
    "ec_range,ec_class",
    (
        # inclusive range start, exclusive range end
        ((0, 1), "success"),
        ((1, 2), "warning"),
        ((2, 3), "error"),
        ((EXIT_ERROR_BASE, EXIT_WARNING_BASE), "error"),
        ((EXIT_WARNING_BASE, EXIT_SIGNAL_BASE), "warning"),
        ((EXIT_SIGNAL_BASE, 256), "signal"),
    ),
)
def test_classify_ec(ec_range, ec_class):
    for ec in range(*ec_range):
        classify_ec(ec) == ec_class


def test_ec_invalid():
    with pytest.raises(ValueError):
        classify_ec(666)
    with pytest.raises(ValueError):
        classify_ec(-1)
    with pytest.raises(TypeError):
        classify_ec(None)


@pytest.mark.parametrize(
    "ec1,ec2,ec_max",
    (
        # same for modern / legacy
        (EXIT_SUCCESS, EXIT_SUCCESS, EXIT_SUCCESS),
        (EXIT_SUCCESS, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        # legacy exit codes
        (EXIT_SUCCESS, EXIT_WARNING, EXIT_WARNING),
        (EXIT_SUCCESS, EXIT_ERROR, EXIT_ERROR),
        (EXIT_WARNING, EXIT_SUCCESS, EXIT_WARNING),
        (EXIT_WARNING, EXIT_WARNING, EXIT_WARNING),
        (EXIT_WARNING, EXIT_ERROR, EXIT_ERROR),
        (EXIT_WARNING, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        (EXIT_ERROR, EXIT_SUCCESS, EXIT_ERROR),
        (EXIT_ERROR, EXIT_WARNING, EXIT_ERROR),
        (EXIT_ERROR, EXIT_ERROR, EXIT_ERROR),
        (EXIT_ERROR, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        # some modern codes
        (EXIT_SUCCESS, EXIT_WARNING_BASE, EXIT_WARNING_BASE),
        (EXIT_SUCCESS, EXIT_ERROR_BASE, EXIT_ERROR_BASE),
        (EXIT_WARNING_BASE, EXIT_SUCCESS, EXIT_WARNING_BASE),
        (EXIT_WARNING_BASE + 1, EXIT_WARNING_BASE + 2, EXIT_WARNING_BASE + 1),
        (EXIT_WARNING_BASE, EXIT_ERROR_BASE, EXIT_ERROR_BASE),
        (EXIT_WARNING_BASE, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        (EXIT_ERROR_BASE, EXIT_SUCCESS, EXIT_ERROR_BASE),
        (EXIT_ERROR_BASE, EXIT_WARNING_BASE, EXIT_ERROR_BASE),
        (EXIT_ERROR_BASE + 1, EXIT_ERROR_BASE + 2, EXIT_ERROR_BASE + 1),
        (EXIT_ERROR_BASE, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
    ),
)
def test_max_ec(ec1, ec2, ec_max):
    assert max_ec(ec1, ec2) == ec_max
