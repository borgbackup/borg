import subprocess
from pathlib import Path

import pytest

SHELL_COMPLETIONS_DIR = Path(__file__).parent / ".." / ".." / ".." / "scripts" / "shell_completions"


def test_bash_completion_is_valid():
    """Test that the Bash completion file is valid Bash syntax."""
    bash_completion_file = SHELL_COMPLETIONS_DIR / "bash" / "borg"
    assert bash_completion_file.is_file()

    # Check if Bash is available
    try:
        subprocess.run(["bash", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("Bash not available")

    # Test whether the Bash completion file can be sourced without errors
    result = subprocess.run(["bash", "-n", str(bash_completion_file)], capture_output=True)
    assert result.returncode == 0, f"Bash completion file has syntax errors: {result.stderr.decode()}"


def test_fish_completion_is_valid():
    """Test that the Fish completion file is valid Fish syntax."""
    fish_completion_file = SHELL_COMPLETIONS_DIR / "fish" / "borg.fish"
    assert fish_completion_file.is_file()

    # Check if Fish is available
    try:
        subprocess.run(["fish", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("Fish not available")

    # Test whether the Fish completion file can be sourced without errors
    result = subprocess.run(["fish", "-c", f"source {str(fish_completion_file)}"], capture_output=True)
    assert result.returncode == 0, f"Fish completion file has syntax errors: {result.stderr.decode()}"


def test_zsh_completion_is_valid():
    """Test that the Zsh completion file is valid Zsh syntax."""
    zsh_completion_file = SHELL_COMPLETIONS_DIR / "zsh" / "_borg"
    assert zsh_completion_file.is_file()

    # Check if Zsh is available
    try:
        subprocess.run(["zsh", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("Zsh not available")

    # Test whether the Zsh completion file can be sourced without errors
    result = subprocess.run(["zsh", "-n", str(zsh_completion_file)], capture_output=True)
    assert result.returncode == 0, f"Zsh completion file has syntax errors: {result.stderr.decode()}"
