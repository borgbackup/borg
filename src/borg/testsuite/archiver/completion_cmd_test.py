import functools
import os
import re
import subprocess
import sys
import tempfile

import pytest

import borg
from ...archiver.completion_cmd import TCSH_SORTBY_FN
from ...archiver.repo_create_cmd import ENCRYPTION_DESCRIPTIONS
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
needs_tcsh = pytest.mark.skipif(not cmd_available("tcsh --version"), reason="Tcsh not available")


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


def _run_zsh_completion_fn(completion_script, setup_code):
    """Run a preamble helper of the completion script in zsh, return subprocess result.

    The generated script can not just be sourced: its tail calls _shtab_borg when it is not
    sourced from a completion context. So we only take the preamble (shtab wraps it into
    markers) and stub compadd, which is how the helpers report their candidates.
    """
    preamble = completion_script.split("# Custom Preamble", 1)[1].split("# End Custom Preamble", 1)[0]
    code = (
        preamble + "\n"
        'compadd() { local a; for a in "$@"; do [[ $a == -* ]] && continue; print -r -- $a; done }\n' + setup_code
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".zsh", delete=False) as f:
        f.write(code)
        script_path = f.name
    try:
        # -f: do not read the startup files
        return subprocess.run(["zsh", "-f", script_path], capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(script_path)


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


def test_tcsh_completion_nontrivial(archivers, request):
    """Verify the generated Tcsh completion is non-trivially sized."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "tcsh")
    assert len(output) > 1000, f"Tcsh completion suspiciously small: {len(output)} chars"
    assert output.count("\n") > 20, f"Tcsh completion suspiciously few lines: {output.count(chr(10))}"


def test_tcsh_completion_dynamic_helpers(archivers, request):
    """Verify the tcsh script has the dynamic archive/tag helpers and uses them."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "tcsh")
    assert "alias _borg_complete_archive " in output, "no archive completion helper"
    assert "alias _borg_complete_tags " in output, "no tag completion helper"
    # the helper scripts are single-quoted csh strings run by sh, see the tcsh preamble
    helper = output.split("set _borg_sh_complete = '", 1)[1].split("'", 1)[0]
    assert "aid:{id}{NL}" in helper and "{archive}{NL}" in helper and "{tags}{NL}" in helper
    assert "`" not in helper, "backquotes in the helper would nest inside the completion rules"
    assert "eval _borg_complete_archive" in output, "archive completion not used for ARCHIVE"
    assert "'n/--tags/`_borg_complete_tags`/'" in output, "tag completion not used for --tags"


def test_tcsh_completion_positional_patterns(archivers, request):
    """Verify positionals of a subcommand get a rule tcsh can apply, e.g. the umount mountpoint."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "tcsh")
    assert "'n/umount/d/'" in output, "no directory completion for the umount mountpoint"
    assert "'n/export/f/'" in output, "no file completion for the key export path"
    # such a pattern is useless inside a `p@N@` rule, tcsh runs those clauses as commands
    for rule in re.findall(r"'p@\d+@`(.*?)`@'", output):
        _setup, _, clauses = rule.partition("; ")  # drop the `set cmd=(...)` part
        for clause in clauses.split("; "):
            action = clause.rpartition(") ")[2]
            assert action.startswith(("echo ", "eval ")), f"bare completion pattern in rule: {rule}"


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


@needs_tcsh
def test_tcsh_completion_syntax(archivers, request):
    """Verify the generated Tcsh completion script has valid syntax."""
    archiver = request.getfixturevalue(archivers)
    output = cmd(archiver, "completion", "tcsh")
    # tcsh doesn't have -n for syntax check like bash/zsh, but we can try to source it
    # and see if it fails. 'tcsh -f -c "source path"'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".tcsh", delete=False) as f:
        f.write(output)
        script_path = f.name
    try:
        # -f: fast start (don't resource .tcshrc)
        result = subprocess.run(["tcsh", "-f", "-c", f"source {script_path}"], capture_output=True)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, f"Generated Tcsh completion has errors: {result.stderr.decode()}"


# -- --sort-by completion (one helper per set of sort keys) -------------------

# (command, name of the shell helper completing its --sort-by)
SORTBY_WIRING = [
    ("repo-list", "_borg_complete_sortby"),
    ("list", "_borg_complete_item_sortby"),
    ("diff", "_borg_complete_diff_sortby"),
]

# (helper, already typed value, keys it must offer, keys it must not offer)
SORTBY_BEHAVIOR = [
    # archive sort keys, must not re-offer an already selected key
    ("_borg_complete_sortby", "timestamp,", ["timestamp,archive"], ["timestamp,timestamp"]),
    # item sort keys, not the archive or item diff ones
    ("_borg_complete_item_sortby", "", ["path", "size", "atime"], ["timestamp", "archive", "size_added"]),
    ("_borg_complete_item_sortby", "size,", ["size,path"], ["size,size"]),
    # item diff sort keys: "size" is a valid key, but does not match the "size_" fragment
    ("_borg_complete_diff_sortby", "size_", ["size_added", "size_removed", "size_diff"], ["size"]),
    ("_borg_complete_diff_sortby", "path,", ["path,size_added"], ["path,path", "path,atime"]),
]


def completion_lines(archivers, request, shell):
    """The generated completion script as a list of lines (on Windows it has CRLF line endings)."""
    return cmd(request.getfixturevalue(archivers), "completion", shell).splitlines()


@pytest.mark.parametrize("command,fn", SORTBY_WIRING)
def test_bash_sortby_wiring(archivers, request, command, fn):
    lines = completion_lines(archivers, request, "bash")
    assert f"_shtab_borg_{command.replace('-', '_')}___sort_by_COMPGEN={fn}" in lines
    assert f"{fn}() {{" in lines


@pytest.mark.parametrize("command,fn", SORTBY_WIRING)
def test_zsh_sortby_wiring(archivers, request, command, fn):
    lines = completion_lines(archivers, request, "zsh")
    block = lines[lines.index(f"_shtab_borg_{command.replace('-', '_')}_options=(") :]
    block = block[: block.index(")")]
    # The ":<label>:<helper>" label is only what zsh displays while completing: shtab used the
    # argument's dest for it and uses its metavar since 1.11.0. Do not pin the label down, just
    # require that --sort-by is wired to our helper.
    assert any(re.search(rf'^\s*"--sort-by\[.*\]:[^:]+:{fn}"', line) for line in block)
    assert f"{fn}() {{" in lines


@pytest.mark.parametrize("command,fn", SORTBY_WIRING)
def test_fish_sortby_wiring(archivers, request, command, fn):
    lines = completion_lines(archivers, request, "fish")
    assert any(
        f"_shtab_borg_using {command}'" in line and " -l sort-by " in line and f'"({fn})"' in line for line in lines
    )
    assert f"function {fn}" in lines


def test_tcsh_sortby_single_rule(archivers, request):
    """tcsh matches by option name only, so all --sort-by options share one helper."""
    lines = completion_lines(archivers, request, "tcsh")
    assert sum(line.count("'n/--sort-by/") for line in lines) == 1
    assert any(f"'n/--sort-by/`{TCSH_SORTBY_FN}`/'" in line for line in lines)
    alias = next(line for line in lines if line.startswith(f"alias {TCSH_SORTBY_FN} "))
    for key in ("timestamp", "atime", "size_added"):  # the union of all the sort keys
        assert f" {key}" in alias


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "tcsh"])
def test_completion_helpers_are_defined(archivers, request, shell):
    """Every _borg_* helper the generated script refers to must also be defined by it."""
    output = "\n".join(completion_lines(archivers, request, shell))
    defined = set(re.findall(r"^(?:function |alias )?(_borg_\w+)\s*(?:\(\)|\(|\s|$)", output, re.M))
    referenced = set(re.findall(r"_borg_complete_\w+|_borg_help_topics", output))
    assert referenced <= defined, f"undefined: {sorted(referenced - defined)}"


@needs_bash
@pytest.mark.parametrize("fn,typed,expected,not_expected", SORTBY_BEHAVIOR)
def test_bash_sortby_keysets(archivers, request, fn, typed, expected, not_expected):
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "bash")

    result = _run_bash_completion_fn(script, f'COMP_WORDS=(borg cmd --sort-by "{typed}")\nCOMP_CWORD=3\n{fn}\n')
    assert result.returncode == 0, f"stderr: {result.stderr}"
    candidates = result.stdout.split()
    assert set(expected) <= set(candidates), f"missing from {candidates}"
    assert not set(not_expected) & set(candidates), f"unexpected in {candidates}"


@needs_zsh
@pytest.mark.parametrize("fn,typed,expected,not_expected", SORTBY_BEHAVIOR)
def test_zsh_sortby_keysets(archivers, request, fn, typed, expected, not_expected):
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "zsh")

    result = _run_zsh_completion_fn(script, f"words=(borg cmd --sort-by '{typed}')\nCURRENT=4\n{fn}\n")
    assert result.returncode == 0, f"stderr: {result.stderr}"
    candidates = result.stdout.split()
    assert set(expected) <= set(candidates), f"missing from {candidates}"
    assert not set(not_expected) & set(candidates), f"unexpected in {candidates}"


@needs_fish
def test_fish_sortby_keysets(archivers, request):
    """Each command's --sort-by completes its own sort keys."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "fish")

    items = _fish_complete_candidates(script, "borg list --sort-by ")
    assert "atime" in items and "timestamp" not in items and "size_added" not in items
    diffs = _fish_complete_candidates(script, "borg diff --sort-by size_added,")
    assert "size_added,path" in diffs and "size_added,size_added" not in diffs
    archives = _fish_complete_candidates(script, "borg repo-list --sort-by ")
    assert "timestamp" in archives and "atime" not in archives


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


# -- issues reported for the generated completions, see #3086 -----------------


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "tcsh"])
def test_completion_help_has_no_rst_markup(archivers, request, shell):
    """The shells show the help as the completion description - RST markup is just noise there."""
    output = "\n".join(completion_lines(archivers, request, shell))
    assert "**(required)**" not in output  # from the --encryption help
    assert "``" not in output  # e.g. from the --json-lines help


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "tcsh"])
def test_completion_uses_invoked_command_name(archivers, request, shell, monkeypatch):
    """A borg installed as e.g. "borg2" must complete borg2 and query the repo via borg2."""
    monkeypatch.setattr(sys, "argv", ["/somewhere/bin/borg2", "completion", shell])
    output = "\n".join(completion_lines(archivers, request, shell))
    assert "borg2 repo-list" in output, "the dynamic completions call some other borg"
    assert "borg repo-list" not in output
    if shell == "fish":  # the only shell registering the command in a greppable way
        assert "complete -c borg2 " in output


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish", "tcsh"])
def test_completion_falls_back_to_borg(archivers, request, shell, monkeypatch):
    """If borg was invoked in a way that gives no usable command name, complete "borg"."""
    monkeypatch.setattr(sys, "argv", ["/somewhere/lib/borg/__main__.py", "completion", shell])
    output = "\n".join(completion_lines(archivers, request, shell))
    assert "borg repo-list" in output
    if shell == "fish":
        assert "complete -c borg " in output


@pytest.mark.parametrize("shell", ["bash", "zsh", "fish"])
def test_completion_repo_is_a_directory(archivers, request, shell):
    """-r/--repo and --other-repo complete local repository directories."""
    lines = completion_lines(archivers, request, shell)
    # how each shell spells "complete directories", and how it refers to the two options
    directory, repo, other_repo = {
        "bash": ("_shtab_compgen_dirs", "_shtab_borg___repo_COMPGEN=", "_shtab_borg_repo_create___other_repo_COMPGEN="),
        "zsh": ("_files -/", "{-r,--repo}", '"--other-repo['),
        "fish": ("__fish_complete_directories", " -l repo ", " -l other-repo "),
    }[shell]
    assert any(repo in line and directory in line for line in lines), "-r/--repo does not complete directories"
    assert any(other_repo in line and directory in line for line in lines), "--other-repo does not complete dirs"


@needs_fish
def test_fish_repo_directory_completion(archivers, request, tmp_path):
    """-r/--repo completes directories, but no files."""
    archiver = request.getfixturevalue(archivers)
    (tmp_path / "somerepo").mkdir()
    (tmp_path / "somefile.txt").touch()
    script = cmd(archiver, "completion", "fish")
    prefix = str(tmp_path / "some")

    for option in ("--repo", "-r"):
        candidates = _fish_complete_candidates(script, f"borg list {option} {prefix}")
        assert any(c.rstrip("/").endswith("somerepo") for c in candidates), f"repo dir missing: {candidates}"
        assert not any(c.endswith("somefile.txt") for c in candidates), f"file offered: {candidates}"


@needs_fish
def test_fish_encryption_mode_descriptions(archivers, request):
    """Each --encryption mode gets its own short description, not the option help."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "fish")
    # _fish_complete_candidates drops the descriptions, so run fish ourselves here
    code = script + "\ncomplete -C'borg repo-create --encryption='\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".fish", delete=False) as f:
        f.write(code)
        script_path = f.name
    try:
        result = subprocess.run(["fish", script_path], capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(script_path)
    assert result.returncode == 0, f"fish failed: {result.stderr}"
    described = dict(line.split("\t", 1) for line in result.stdout.splitlines() if "\t" in line)
    for mode, description in ENCRYPTION_DESCRIPTIONS.items():
        assert described[f"--encryption={mode}"] == description


@needs_zsh
def test_zsh_encryption_mode_descriptions(archivers, request):
    """The zsh helper offers all modes, each with the mode name and its description."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "zsh")
    # the harness' compadd stub prints the candidates - replace it by one printing the descriptions
    # (zsh scopes locals dynamically, so the array the helper declares is visible in here)
    setup = "compadd() { print -rl -- $choices $descriptions }\n_borg_complete_encryption\n"
    result = _run_zsh_completion_fn(script, setup)
    assert result.returncode == 0, f"stderr: {result.stderr}"
    output = result.stdout.splitlines()
    for mode, description in ENCRYPTION_DESCRIPTIONS.items():
        assert mode in output
        assert f"{mode}  -- {description}" in output


@pytest.mark.parametrize("shell", ["bash", "tcsh"])
def test_encryption_modes_without_descriptions(archivers, request, shell):
    """bash and tcsh have no completion descriptions, they just complete the mode names."""
    output = "\n".join(completion_lines(archivers, request, shell))
    # the helper is needed even without descriptions: shtab lets it win over the action's choices
    assert "_borg_complete_encryption" in output
    assert " ".join(ENCRYPTION_DESCRIPTIONS) in output  # the plain mode names
    for description in ENCRYPTION_DESCRIPTIONS.values():
        assert description not in output


@needs_bash
def test_bash_encryption_mode_completion(archivers, request):
    """The bash helper offers all encryption modes."""
    archiver = request.getfixturevalue(archivers)
    script = cmd(archiver, "completion", "bash")

    result = _run_bash_completion_fn(script, "_borg_complete_encryption ''\n")
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert result.stdout.split() == list(ENCRYPTION_DESCRIPTIONS)
