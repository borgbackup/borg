import pytest

from ...helpers.nanorst import rst_to_text


def test_inline():
    assert rst_to_text("*foo* and ``bar``.") == "foo and bar."


def test_inline_spread():
    assert rst_to_text("*foo and bar, thusly\nfoobar*.") == "foo and bar, thusly\nfoobar."


def test_comment_inline():
    assert rst_to_text("Foo and Bar\n.. foo\nbar") == "Foo and Bar\n.. foo\nbar"


def test_inline_escape():
    assert rst_to_text('Such as "\\*" characters.') == 'Such as "*" characters.'


def test_comment():
    assert rst_to_text("Foo and Bar\n\n.. foo\nbar") == "Foo and Bar\n\nbar"


def test_directive_note():
    assert rst_to_text(".. note::\n   Note this and that") == "Note:\n   Note this and that"


def test_ref():
    references = {"foo": "baz"}
    assert rst_to_text("See :ref:`fo\no`.", references=references) == "See baz."


def test_undefined_ref():
    with pytest.raises(ValueError) as exc_info:
        rst_to_text("See :ref:`foo`.")
    assert "Undefined reference" in str(exc_info.value)


def test_code_block_end_of_string():
    # check that there is no unexpected exception if a code block
    # is not followed by blank lines, but the string just ends.
    assert rst_to_text("This is a code block::\n\n    borg --help") == "This is a code block:\n\n    borg --help"


def test_code_block_indented_context():
    # a code block inside a definition list: the following text is indented, but less than
    # the code block's contents, so it ends the code block and gets markup-processed again.
    rst = "term\n    Foo::\n\n        code\n\n    Continued ``text``.\n"
    assert rst_to_text(rst) == "term\n    Foo:\n\n        code\n\n    Continued text.\n"


def test_code_block_less_indented_than_four():
    # code blocks indented by less than 4 spaces are recognized, too
    rst = "Foo::\n\n  code\n\nBar ``baz``.\n"
    assert rst_to_text(rst) == "Foo:\n\n  code\n\nBar baz.\n"
