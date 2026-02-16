import os
import subprocess
import tempfile

import pytest

from . import cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


def _bash_available():
    try:
        subprocess.run(["bash", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _run_bash_completion_fn(completion_script, setup_code):
    """Source the completion script in bash and run setup_code, return subprocess result."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".bash", delete=False) as f:
        f.write(completion_script)
        f.flush()
        script_path = f.name
    try:
        result = subprocess.run(
            ["bash", "-c", f"source {script_path}\n{setup_code}"], capture_output=True, text=True, timeout=30
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


def test_bash_completion_syntax(archivers, request):
    """Verify the generated Bash completion script has valid syntax."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "bash")

    if not _bash_available():
        pytest.skip("Bash not available")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".bash", delete=False) as f:
        f.write(output)
        f.flush()
        script_path = f.name
    try:
        result = subprocess.run(["bash", "-n", script_path], capture_output=True)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, f"Generated Bash completion has syntax errors: {result.stderr.decode()}"


def test_zsh_completion_syntax(archivers, request):
    """Verify the generated Zsh completion script has valid syntax."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "zsh")

    try:
        subprocess.run(["zsh", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("Zsh not available")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".zsh", delete=False) as f:
        f.write(output)
        f.flush()
        script_path = f.name
    try:
        result = subprocess.run(["zsh", "-n", script_path], capture_output=True)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, f"Generated Zsh completion has syntax errors: {result.stderr.decode()}"


# -- borg-specific preamble function behavior (bash) --------------------------


def test_bash_sortby_dedup(archivers, request):
    """_borg_complete_sortby should not re-offer already-selected sort keys."""
    if not _bash_available():
        pytest.skip("Bash not available")
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


def test_bash_filescachemode_exclusivity(archivers, request):
    """_borg_complete_filescachemode should enforce ctime/mtime and disabled mutual exclusion."""
    if not _bash_available():
        pytest.skip("Bash not available")
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


def test_bash_archive_name_completion(archivers, request):
    """_borg_complete_archive should complete archive names from a real repo."""
    if not _bash_available():
        pytest.skip("Bash not available")
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


def test_bash_archive_aid_completion(archivers, request):
    """_borg_complete_archive should complete aid: prefixed archive IDs."""
    if not _bash_available():
        pytest.skip("Bash not available")
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
