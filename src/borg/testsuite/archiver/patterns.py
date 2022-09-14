from ...archiver._common import build_filter
from ...constants import *  # NOQA
from ...patterns import IECommand, PatternMatcher, parse_pattern
from ...item import Item


class TestBuildFilter:
    def test_basic(self):
        matcher = PatternMatcher()
        matcher.add([parse_pattern("included")], IECommand.Include)
        filter = build_filter(matcher, 0)
        assert filter(Item(path="included"))
        assert filter(Item(path="included/file"))
        assert not filter(Item(path="something else"))

    def test_empty(self):
        matcher = PatternMatcher(fallback=True)
        filter = build_filter(matcher, 0)
        assert filter(Item(path="anything"))

    def test_strip_components(self):
        matcher = PatternMatcher(fallback=True)
        filter = build_filter(matcher, strip_components=1)
        assert not filter(Item(path="shallow"))
        assert not filter(Item(path="shallow/"))  # can this even happen? paths are normalized...
        assert filter(Item(path="deep enough/file"))
        assert filter(Item(path="something/dir/file"))
