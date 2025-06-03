import os
import shutil
import subprocess

import pytest

from ... import xattr
from ...constants import *  # NOQA
from .. import changedir
from . import assert_dirs_equal, _extract_hardlinks_setup, cmd, requires_hardlinks, RK_ENCRYPTION
from . import create_test_files, create_regular_file
from . import generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,remote,binary")  # NOQA


def have_gnutar():
    if not shutil.which("tar"):
        return False
    popen = subprocess.Popen(["tar", "--version"], stdout=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    return b"GNU tar" in stdout


requires_gnutar = pytest.mark.skipif(not have_gnutar(), reason="GNU tar must be installed for this test.")
requires_gzip = pytest.mark.skipif(not shutil.which("gzip"), reason="gzip must be installed for this test.")


@requires_gnutar
def test_export_tar(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "export-tar", "test", "simple.tar", "--progress", "--tar-format=GNU")
    with changedir("output"):
        # This probably assumes GNU tar. Note -p switch to extract permissions regardless of umask.
        subprocess.check_call(["tar", "xpf", "../simple.tar", "--warning=no-timestamp"])
    assert_dirs_equal("input", "output/input", ignore_flags=True, ignore_xattrs=True, ignore_ns=True)


@requires_gnutar
@requires_gzip
def test_export_tar_gz(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    test_list = cmd(archiver, "export-tar", "test", "simple.tar.gz", "--list", "--tar-format=GNU")
    assert "input/file1\n" in test_list
    assert "input/dir2\n" in test_list
    with changedir("output"):
        subprocess.check_call(["tar", "xpf", "../simple.tar.gz", "--warning=no-timestamp"])
    assert_dirs_equal("input", "output/input", ignore_flags=True, ignore_xattrs=True, ignore_ns=True)


@requires_gnutar
@requires_gzip
def test_export_tar_strip_components(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    test_list = cmd(archiver, "export-tar", "test", "simple.tar", "--strip-components=1", "--list", "--tar-format=GNU")
    # --list's path are those before processing with --strip-components
    assert "input/file1\n" in test_list
    assert "input/dir2\n" in test_list
    with changedir("output"):
        subprocess.check_call(["tar", "xpf", "../simple.tar", "--warning=no-timestamp"])
    assert_dirs_equal("input", "output/", ignore_flags=True, ignore_xattrs=True, ignore_ns=True)


@requires_hardlinks
@requires_gnutar
def test_export_tar_strip_components_links(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _extract_hardlinks_setup(archiver)
    cmd(archiver, "export-tar", "test", "output.tar", "--strip-components=2", "--tar-format=GNU")
    with changedir("output"):
        subprocess.check_call(["tar", "xpf", "../output.tar", "--warning=no-timestamp"])
        assert os.stat("hardlink").st_nlink == 2
        assert os.stat("subdir/hardlink").st_nlink == 2
        assert os.stat("aaaa").st_nlink == 2
        assert os.stat("source2").st_nlink == 2


@requires_hardlinks
@requires_gnutar
def test_extract_hardlinks_tar(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _extract_hardlinks_setup(archiver)
    cmd(archiver, "export-tar", "test", "output.tar", "input/dir1", "--tar-format=GNU")
    with changedir("output"):
        subprocess.check_call(["tar", "xpf", "../output.tar", "--warning=no-timestamp"])
        assert os.stat("input/dir1/hardlink").st_nlink == 2
        assert os.stat("input/dir1/subdir/hardlink").st_nlink == 2
        assert os.stat("input/dir1/aaaa").st_nlink == 2
        assert os.stat("input/dir1/source2").st_nlink == 2


def test_import_tar(archivers, request, tar_format="PAX"):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hardlinks become separate files
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "simple.tar", f"--tar-format={tar_format}")
    cmd(archiver, "import-tar", "dst", "simple.tar")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


def test_import_unusual_tar(archivers, request):
    archiver = request.getfixturevalue(archivers)

    # Contains these, unusual entries:
    # /foobar
    # ./bar
    # ./foo2/
    # ./foo//bar
    # ./
    tar_archive = os.path.join(os.path.dirname(__file__), "unusual_paths.tar")
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "import-tar", "dst", tar_archive)
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {"foobar", "bar", "foo2", "foo/bar", "."}


def test_import_tar_with_dotdot(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:  # the test checks for a raised exception. that can't work if the code runs in a separate process.
        pytest.skip("does not work with binaries")

    # Contains this file:
    # ../../../../etc/shadow
    tar_archive = os.path.join(os.path.dirname(__file__), "dotdot_path.tar")
    cmd(archiver, "repo-create", "--encryption=none")
    with pytest.raises(ValueError, match="unexpected '..' element in path '../../../../etc/shadow'"):
        cmd(archiver, "import-tar", "dst", tar_archive, exit_code=2)


@requires_gzip
def test_import_tar_gz(archivers, request, tar_format="GNU"):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hardlinks become separate files
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "simple.tgz", f"--tar-format={tar_format}")
    cmd(archiver, "import-tar", "dst", "simple.tgz")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


@requires_gnutar
def test_import_concatenated_tar_with_ignore_zeros(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hardlinks become separate files
    os.unlink("input/flagfile")
    with changedir("input"):
        subprocess.check_call(["tar", "cf", "file1.tar", "file1"])
        subprocess.check_call(["tar", "cf", "the_rest.tar", "--exclude", "file1*", "."])
        with open("concatenated.tar", "wb") as concatenated:
            with open("file1.tar", "rb") as file1:
                concatenated.write(file1.read())
            # Clean up for assert_dirs_equal.
            os.unlink("file1.tar")

            with open("the_rest.tar", "rb") as the_rest:
                concatenated.write(the_rest.read())
            # Clean up for assert_dirs_equal.
            os.unlink("the_rest.tar")

    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "import-tar", "--ignore-zeros", "dst", "input/concatenated.tar")
    # Clean up for assert_dirs_equal.
    os.unlink("input/concatenated.tar")

    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output", ignore_ns=True, ignore_xattrs=True)


@requires_gnutar
def test_import_concatenated_tar_without_ignore_zeros(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hardlinks become separate files
    os.unlink("input/flagfile")

    with changedir("input"):
        subprocess.check_call(["tar", "cf", "file1.tar", "file1"])
        subprocess.check_call(["tar", "cf", "the_rest.tar", "--exclude", "file1*", "."])
        with open("concatenated.tar", "wb") as concatenated:
            with open("file1.tar", "rb") as file1:
                concatenated.write(file1.read())
            with open("the_rest.tar", "rb") as the_rest:
                concatenated.write(the_rest.read())
            os.unlink("the_rest.tar")
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "import-tar", "dst", "input/concatenated.tar")

    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    # Negative test -- assert that only file1 has been extracted, and the_rest has been ignored
    # due to zero-filled block marker.
    assert os.listdir("output") == ["file1"]


def test_roundtrip_pax_borg(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.remove("input/flagfile")  # this would be automagically excluded due to NODUMP
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "simple.tar", "--tar-format=BORG")
    cmd(archiver, "import-tar", "dst", "simple.tar")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input")


def test_roundtrip_pax_xattrs(archivers, request):
    archiver = request.getfixturevalue(archivers)
    if not xattr.is_enabled(archiver.input_path):
        pytest.skip("xattrs not supported")
    create_regular_file(archiver.input_path, "file")
    original_path = os.path.join(archiver.input_path, "file")
    xa_key, xa_value = b"user.xattrtest", b"not valid utf-8: \xff"
    xattr.setxattr(original_path.encode(), xa_key, xa_value)
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "xattrs.tar", "--tar-format=PAX")
    cmd(archiver, "import-tar", "dst", "xattrs.tar")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
        extracted_path = os.path.abspath("input/file")
        xa_value_extracted = xattr.getxattr(extracted_path.encode(), xa_key)
    assert xa_value_extracted == xa_value
