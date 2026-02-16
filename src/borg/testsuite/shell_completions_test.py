import subprocess
from pathlib import Path

import pytest

SHELL_COMPLETIONS_DIR = Path(__file__).parent / ".." / ".." / ".." / "scripts" / "shell_completions"


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
