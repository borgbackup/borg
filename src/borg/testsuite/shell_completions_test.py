import os
import subprocess
import pytest

SHELL_COMPLETIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts", "shell_completions")


def test_bash_completion_is_valid():
    """Test that the bash completion file is valid bash syntax."""
    bash_completion_file = os.path.join(SHELL_COMPLETIONS_DIR, "bash", "borg")
    assert os.path.isfile(bash_completion_file)

    # Check if bash is available
    try:
        subprocess.run(["bash", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("bash not available")

    # Test if the bash completion file can be sourced without errors
    result = subprocess.run(["bash", "-n", bash_completion_file], capture_output=True)
    assert result.returncode == 0, f"Bash completion file has syntax errors: {result.stderr.decode()}"


def test_fish_completion_is_valid():
    """Test that the fish completion file is valid fish syntax."""
    fish_completion_file = os.path.join(SHELL_COMPLETIONS_DIR, "fish", "borg.fish")
    assert os.path.isfile(fish_completion_file)

    # Check if fish is available
    try:
        subprocess.run(["fish", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("fish not available")

    # Test if the fish completion file can be sourced without errors
    result = subprocess.run(["fish", "-c", f"source {fish_completion_file}"], capture_output=True)
    assert result.returncode == 0, f"Fish completion file has syntax errors: {result.stderr.decode()}"


def test_zsh_completion_is_valid():
    """Test that the zsh completion file is valid zsh syntax."""
    zsh_completion_file = os.path.join(SHELL_COMPLETIONS_DIR, "zsh", "_borg")
    assert os.path.isfile(zsh_completion_file)

    # Check if zsh is available
    try:
        subprocess.run(["zsh", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        pytest.skip("zsh not available")

    # Test if the zsh completion file can be sourced without errors
    result = subprocess.run(["zsh", "-n", zsh_completion_file], capture_output=True)
    assert result.returncode == 0, f"Zsh completion file has syntax errors: {result.stderr.decode()}"
