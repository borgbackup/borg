from . import cmd, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


def test_bash_completion(archivers, request):
    """Ensure the generated Bash completion includes our helper."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "bash")
    assert "_borg_complete_aid() {" in output
    assert "_borg_complete_sortby() {" in output


def test_zsh_completion(archivers, request):
    """Ensure the generated Zsh completion includes our helper."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "zsh")
    assert "_borg_complete_aid() {" in output
    assert "_borg_complete_sortby() {" in output
