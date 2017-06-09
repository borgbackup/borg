
import pytest

from ..nanorst import rst_to_text


def test_inline():
    assert rst_to_text('*foo* and ``bar``.') == 'foo and bar.'


def test_inline_spread():
    assert rst_to_text('*foo and bar, thusly\nfoobar*.') == 'foo and bar, thusly\nfoobar.'


def test_comment_inline():
    assert rst_to_text('Foo and Bar\n.. foo\nbar') == 'Foo and Bar\n.. foo\nbar'


def test_inline_escape():
    assert rst_to_text('Such as "\\*" characters.') == 'Such as "*" characters.'


def test_comment():
    assert rst_to_text('Foo and Bar\n\n.. foo\nbar') == 'Foo and Bar\n\nbar'


def test_directive_note():
    assert rst_to_text('.. note::\n   Note this and that') == 'Note:\n   Note this and that'


def test_ref():
    references = {
        'foo': 'baz'
    }
    assert rst_to_text('See :ref:`fo\no`.', references=references) == 'See baz.'


def test_undefined_ref():
    with pytest.raises(ValueError) as exc_info:
        rst_to_text('See :ref:`foo`.')
    assert 'Undefined reference' in str(exc_info.value)
