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
<<<<<<< Updated upstream
=======

########################################################################

def test_display_diy_coverage_report_before_tests():
    """
    Attention:
    Run using -s flag.
   
    pytest -s src/borg/testsuite/helpers/nanorst_test.py

    This counts how many branches were hit. Each branch has an id.
    """
    print("\n" + "="*30)
    print("DIY BRANCH COVERAGE REPORT: BEFORE TESTS")
    print("="*30)
    
    for i in range(1, 26):
        status = "hit" if coverage_hits.get(i) else "not hit"
        print(f"Branch {i}: {status}")
    
    print("-" * 30)
    
    total_branches = 25
    hit_count = sum(1 for hit in coverage_hits.values() if hit)
    percentage = (hit_count / total_branches) * 100
    
    print(f"Total Branches: {total_branches}")
    print(f"Branches Hit:   {hit_count}")
    print(f"Coverage:       {percentage:.1f}%")
    print("="*30)

def test_code_block_coverage():
    """
    This tests that rST :: is handled (enters literal mode) and converted to regular text
    """
    content = "Example::\n\n    code\n\nRegular text"
    result = rst_to_text(content)
    
    assert "Example::\n" not in result
    assert "Regular text" in result

def test_bold_text_coverage():
    """
    Hit, enter bold state/block and hit exit bold state/block).
    """
    content = "This is **bold** text"
    result = rst_to_text(content)
    
    assert "bold" in result
    assert "**" not in result

def test_display_diy_coverage_report_after_tests():
    """
    Attention:
    Run using -s flag: 
    pytest -s src/borg/testsuite/helpers/nanorst_test.py

    This counts how many branches were hit after the tests.
    """
    print("\n" + "="*30)
    print("DIY BRANCH COVERAGE REPORT: AFTER TESTS")
    print("="*30)
    
    for i in range(1, 26):
        status = "hit" if coverage_hits.get(i) else "not hit"
        print(f"Branch {i}: {status}")
    
    print("-" * 30)
    
    total_branches = 25
    hit_count = sum(1 for hit in coverage_hits.values() if hit)
    percentage = (hit_count / total_branches) * 100
    
    print(f"Total Branches: {total_branches}")
    print(f"Branches Hit:   {hit_count}")
    print(f"Coverage:       {percentage:.1f}%")
    print("="*30)
>>>>>>> Stashed changes
