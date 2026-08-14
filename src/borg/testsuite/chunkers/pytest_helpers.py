"""Chunker test helpers that require pytest.

These must not live in this package's __init__.py: borg.selftest imports the *_self_test.py
modules from this package, so the package __init__ runs on every borg invocation - and a
normal borg install has no pytest.
"""

import pytest


def chunker_with_kernel(monkeypatch, envvar, kernel, make):
    """Build a chunker with <envvar> set to <kernel>, or skip if it cannot run here.

    Which kernels exist depends on the build (compiler support) and on the CPU, so a
    kernel that cannot be selected is not a failure - the test is skipped, carrying
    the reason the chunker gave, so `pytest -rs` shows which kernels a machine covered.
    Requesting an unusable kernel raising (rather than falling back) is itself tested,
    see test_kernel_env_rejects_unusable.
    """
    monkeypatch.setenv(envvar, kernel)
    try:
        chunker = make()
    except ValueError as err:
        pytest.skip(str(err))
    assert chunker.kernel == kernel  # we must have got what we asked for, not a fallback
    return chunker
