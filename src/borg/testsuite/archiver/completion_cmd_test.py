import functools
import os
import subprocess
import sys
import tempfile

import pytest

import borg
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


@functools.lru_cache
def bash_version():
    """Major version of the bash on PATH (0 if unavailable)."""
    try:
        out = subprocess.run(["bash", "-c", "echo $BASH_VERSINFO"], capture_output=True, text=True, check=True)
        return int(out.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError, ValueError):
        return 0


# the completion script shtab generates uses mapfile, which needs bash >= 4
# (macOS still ships bash 3.2)
needs_bash4 = pytest.mark.skipif(bash_version() < 4, reason="Bash >= 4 not available")
needs_zsh = pytest.mark.skipif(not cmd_available("zsh --version"), reason="Zsh not available")
needs_fish = pytest.mark.skipif(not cmd_available("fish --version"), reason="Fish not available")


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


def _fish_quote(text):
    """Escape text for inclusion in a single-quoted fish string."""
    return text.replace("\\", "\\\\").replace("'", "\\'")


def _fish_complete_candidates(completion_script, cmdline, path_prepend=None):
    """Source the completion script in fish, return the completion candidates for cmdline."""
    code = completion_script + f"\ncomplete -C'{_fish_quote(cmdline)}'\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".fish", delete=False) as f:
        f.write(code)
        script_path = f.name
    env = dict(os.environ)
    if path_prepend:
        env["PATH"] = path_prepend + os.pathsep + env.get("PATH", "")
    try:
        result = subprocess.run(["fish", script_path], capture_output=True, text=True, timeout=120, env=env)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, f"fish failed: {result.stderr}"
    # each output line is "candidate<TAB>description" (or just "candidate")
    return [line.split("\t")[0] for line in result.stdout.splitlines() if line.strip()]


def _borg_shim_dir(tmp_path):
    """Create a dir with a borg script that runs the borg under test, for use inside fish."""
    src_dir = os.path.dirname(os.path.dirname(os.path.abspath(borg.__file__)))
    shim_dir = tmp_path / "borg-shim"
    shim_dir.mkdir()
    shim = shim_dir / "borg"
    shim.write_text(
        f'#!/bin/sh\nexport PYTHONPATH="{src_dir}${{PYTHONPATH:+:$PYTHONPATH}}"\nexec "{sys.executable}" -m borg "$@"\n'
    )
    shim.chmod(0o755)
    return str(shim_dir)


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


def test_fish_completion_nontrivial(archivers, request):
    """Verify the generated Fish completion is non-trivially sized."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "fish")
    assert len(output) > 5000, f"Fish completion suspiciously small: {len(output)} chars"
    assert output.count("\n") > 100, f"Fish completion suspiciously few lines: {output.count(chr(10))}"


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


@needs_fish
def test_fish_completion_syntax(archivers, request):
    """Verify the generated Fish completion script has valid syntax."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "fish")
    result = _check_shell_syntax(output, "fish", ".fish")
    assert result.returncode == 0, f"Generated Fish completion has syntax errors: {result.stderr.decode()}"


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


# -- borg-specific completion behavior (fish) ---------------------------------


@needs_fish
def test_fish_subcommand_completion(archivers, request):
    """Command names should be completed at the top level and inside command groups."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "fish")

    candidates = _fish_complete_candidates(script, "borg ")
    for name in ("create", "extract", "repo-list", "key", "debug"):
        assert name in candidates, f"expected command {name} in: {candidates}"

    candidates = _fish_complete_candidates(script, "borg key ")
    for name in ("export", "import", "change-passphrase"):
        assert name in candidates, f"expected key subcommand {name} in: {candidates}"


@needs_fish
def test_fish_option_completion(archivers, request):
    """Option names and static option values should be completed."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "fish")

    candidates = _fish_complete_candidates(script, "borg create --compres")
    assert "--compression" in candidates, f"expected --compression in: {candidates}"

    candidates = _fish_complete_candidates(script, "borg create --compression ")
    assert "lz4" in candidates, f"expected lz4 in: {candidates}"
    assert "zstd,3" in candidates, f"expected zstd,3 in: {candidates}"


@needs_fish
def test_fish_sortby_dedup(archivers, request):
    """_borg_complete_sortby should not re-offer already-selected sort keys."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "fish")

    candidates = _fish_complete_candidates(script, "borg repo-list --sort-by timestamp,")
    assert "timestamp,archive" in candidates, f"expected timestamp,archive in: {candidates}"
    assert "timestamp,timestamp" not in candidates, f"timestamp was re-offered: {candidates}"


@needs_fish
def test_fish_filescachemode_exclusivity(archivers, request):
    """_borg_complete_filescachemode should enforce ctime/mtime and disabled mutual exclusion."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "fish")

    candidates = _fish_complete_candidates(script, "borg create --files-cache ctime,")
    assert "ctime,size" in candidates, f"expected ctime,size in: {candidates}"
    assert "ctime,mtime" not in candidates, f"mtime offered after ctime: {candidates}"
    assert "ctime,disabled" not in candidates, f"disabled offered after ctime: {candidates}"

    candidates = _fish_complete_candidates(script, "borg create --files-cache disabled,")
    assert candidates == [], f"completions offered after disabled: {candidates}"


@needs_fish
def test_fish_path_completion(archivers, request, tmp_path):
    """Arguments taking a filesystem path complete files/directories."""
    archiver = request.getfixturevalue(archivers)
    (tmp_path / "somefile.txt").touch()
    (tmp_path / "somedir").mkdir()
    script = cmd(archiver, "completion", "fish")
    prefix = str(tmp_path / "some")

    # positional PATH of "borg create" ...
    candidates = _fish_complete_candidates(script, f"borg create archivename {prefix}")
    assert any(c.endswith("somefile.txt") for c in candidates), f"file missing: {candidates}"
    # ... and the value of an option taking a file
    candidates = _fish_complete_candidates(script, f"borg create --exclude-from {prefix}")
    assert any(c.endswith("somefile.txt") for c in candidates), f"file missing: {candidates}"
    # arguments taking a directory only offer directories
    candidates = _fish_complete_candidates(script, f"borg mount --repo /repo archivename {prefix}")
    assert any(c.rstrip("/").endswith("somedir") for c in candidates), f"dir missing: {candidates}"
    assert not any(c.endswith("somefile.txt") for c in candidates), f"file offered for MOUNTPOINT: {candidates}"


@needs_bash4
def test_bash_path_completion(archivers, request, tmp_path):
    """Arguments taking a filesystem path complete files in bash, too."""
    archiver = request.getfixturevalue(archivers)
    (tmp_path / "somefile.txt").touch()
    script = cmd(archiver, "completion", "bash")
    prefix = str(tmp_path / "some")

    result = _run_bash_completion_fn(
        script,
        f'COMP_WORDS=(borg create --exclude-from "{prefix}")\n'
        f"COMP_CWORD=3\n"
        f"_shtab_borg\n"
        f'printf "%s\\n" "${{COMPREPLY[@]}}"\n',
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "somefile.txt" in result.stdout, f"file missing: {result.stdout}"


@needs_fish
def test_fish_archive_name_completion(archivers, request, tmp_path):
    """Archive names should be completed from a real repo."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "mybackup-2024", archiver.input_path)
    cmd(archiver, "create", "mybackup-2025", archiver.input_path)

    script = cmd(archiver, "completion", "fish")
    repo = archiver.repository_path

    candidates = _fish_complete_candidates(
        script, f"borg delete --repo {repo} mybackup", path_prepend=_borg_shim_dir(tmp_path)
    )
    assert "mybackup-2024" in candidates, f"archive name missing: {candidates}"
    assert "mybackup-2025" in candidates, f"archive name missing: {candidates}"


@needs_fish
def test_fish_archive_aid_completion(archivers, request, tmp_path):
    """aid: prefixed archive IDs should be completed from a real repo."""
    archiver = request.getfixturevalue(archivers)
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "testarchive", archiver.input_path)

    script = cmd(archiver, "completion", "fish")
    repo = archiver.repository_path

    candidates = _fish_complete_candidates(
        script, f"borg info --repo {repo} aid:", path_prepend=_borg_shim_dir(tmp_path)
    )
    assert len(candidates) >= 1, "Expected at least one archive ID completion"
    for candidate in candidates:
        assert candidate.startswith("aid:"), f"Expected aid: prefix, got: {candidate}"
