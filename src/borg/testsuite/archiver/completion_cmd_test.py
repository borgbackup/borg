import functools
import os
import subprocess
import tempfile

import pytest

from . import cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


@functools.lru_cache
def cmd_available(cmd):
    """Check if a shell command is available."""
    try:
        subprocess.run(cmd.split(), capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


needs_bash = pytest.mark.skipif(not cmd_available("bash --version"), reason="Bash not available")
needs_zsh = pytest.mark.skipif(not cmd_available("zsh --version"), reason="Zsh not available")


def _run_bash_completion_fn(completion_script, setup_code):
    """Source the completion script in bash and run setup_code, return subprocess result."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bash", delete=False) as f:
        f.write(completion_script)
        script_path = f.name
    try:
        result = subprocess.run(
            ["bash", "-c", f"source {script_path}\n{setup_code}"], capture_output=True, text=True, timeout=120
        )
    finally:
        os.unlink(script_path)
    return result


# -- output sanity checks -----------------------------------------------------


def test_bash_completion_nontrivial(archivers, request):
    """Verify the generated Bash completion is non-trivially sized."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "bash")
    assert len(output) > 5000, f"Bash completion suspiciously small: {len(output)} chars"
    assert output.count("\n") > 100, f"Bash completion suspiciously few lines: {output.count(chr(10))}"


def test_zsh_completion_nontrivial(archivers, request):
    """Verify the generated Zsh completion is non-trivially sized."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "zsh")
    assert len(output) > 5000, f"Zsh completion suspiciously small: {len(output)} chars"
    assert output.count("\n") > 100, f"Zsh completion suspiciously few lines: {output.count(chr(10))}"


# -- syntax validation --------------------------------------------------------


def _check_shell_syntax(script_content, shell, suffix):
    """Write script_content to a temp file and verify syntax with ``shell -n``."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
        f.write(script_content)
        script_path = f.name
    try:
        result = subprocess.run([shell, "-n", script_path], capture_output=True)
    finally:
        os.unlink(script_path)
    return result


@needs_bash
def test_bash_completion_syntax(archivers, request):
    """Verify the generated Bash completion script has valid syntax."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "bash")
    result = _check_shell_syntax(output, "bash", ".bash")
    assert result.returncode == 0, f"Generated Bash completion has syntax errors: {result.stderr.decode()}"


@needs_zsh
def test_zsh_completion_syntax(archivers, request):
    """Verify the generated Zsh completion script has valid syntax."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "zsh")
    result = _check_shell_syntax(output, "zsh", ".zsh")
    assert result.returncode == 0, f"Generated Zsh completion has syntax errors: {result.stderr.decode()}"


# -- borg-specific preamble function behavior (bash) --------------------------


@needs_bash
def test_bash_sortby_dedup(archivers, request):
    """_borg_complete_sortby should not re-offer already-selected sort keys."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "bash")

    # Simulate: user typed "borg repo-list --sort-by timestamp,"
    # The function should offer remaining keys but NOT "timestamp" again.
    result = _run_bash_completion_fn(
        script, 'COMP_WORDS=(borg repo-list --sort-by "timestamp,")\n' "COMP_CWORD=3\n" "_borg_complete_sortby\n"
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    lines = [line for line in result.stdout.strip().splitlines() if line.strip()]
    # "timestamp" must not appear as a standalone completion candidate
    bare_keys = [line.rsplit(",", 1)[-1] for line in lines]
    assert "timestamp" not in bare_keys, f"timestamp was re-offered: {lines}"
    # Other keys like "archive" should be offered
    assert any("archive" in line for line in lines), f"expected 'archive' in completions: {lines}"


@needs_bash
def test_bash_filescachemode_exclusivity(archivers, request):
    """_borg_complete_filescachemode should enforce ctime/mtime and disabled mutual exclusion."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "bash")

    # After selecting "ctime,", mtime should not be offered
    result = _run_bash_completion_fn(
        script, 'COMP_WORDS=(borg create --files-cache "ctime,")\n' "COMP_CWORD=3\n" "_borg_complete_filescachemode\n"
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    bare_keys = [line.rsplit(",", 1)[-1] for line in result.stdout.strip().splitlines() if line.strip()]
    assert "mtime" not in bare_keys, f"mtime offered after ctime: {bare_keys}"
    assert "disabled" not in bare_keys, f"disabled offered after ctime: {bare_keys}"

    # After selecting "disabled,", nothing should be offered
    result2 = _run_bash_completion_fn(
        script,
        'COMP_WORDS=(borg create --files-cache "disabled,")\n' "COMP_CWORD=3\n" "_borg_complete_filescachemode\n",
    )
    assert result2.returncode == 0
    assert result2.stdout.strip() == "", f"completions offered after disabled: {result2.stdout}"

    # After selecting "size,", disabled should not be offered
    result3 = _run_bash_completion_fn(
        script, 'COMP_WORDS=(borg create --files-cache "size,")\n' "COMP_CWORD=3\n" "_borg_complete_filescachemode\n"
    )
    assert result3.returncode == 0
    bare_keys3 = [line.rsplit(",", 1)[-1] for line in result3.stdout.strip().splitlines() if line.strip()]
    assert "disabled" not in bare_keys3, f"disabled offered after size: {bare_keys3}"


@needs_bash
def test_bash_archive_name_completion(archivers, request):
    """_borg_complete_archive should complete archive names from a real repo."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "mybackup-2024", archiver.input_path)
    cmd(archiver, "create", "mybackup-2025", archiver.input_path)

    script = cmd(archiver, "completion", "bash")
    repo = archiver.repository_path

    result = _run_bash_completion_fn(
        script, f'COMP_WORDS=(borg delete --repo "{repo}" "mybackup")\n' f"COMP_CWORD=4\n" f"_borg_complete_archive\n"
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "mybackup-2024" in result.stdout, f"archive name missing: {result.stdout}"
    assert "mybackup-2025" in result.stdout, f"archive name missing: {result.stdout}"


@needs_bash
def test_bash_archive_aid_completion(archivers, request):
    """_borg_complete_archive should complete aid: prefixed archive IDs."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "testarchive", archiver.input_path)

    script = cmd(archiver, "completion", "bash")
    repo = archiver.repository_path

    result = _run_bash_completion_fn(
        script, f'COMP_WORDS=(borg info --repo "{repo}" "aid:")\n' f"COMP_CWORD=4\n" f"_borg_complete_archive\n"
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    lines = [line for line in result.stdout.strip().splitlines() if line.strip()]
    assert len(lines) >= 1, "Expected at least one archive ID completion"
    for line in lines:
        assert line.startswith("aid:"), f"Expected aid: prefix, got: {line}"
