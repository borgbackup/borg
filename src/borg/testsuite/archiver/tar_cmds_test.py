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
from ...platform import acl_get, acl_set
from ..platform.platform_test import skipif_not_linux, skipif_acls_not_working

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


@requires_gnutar
def test_import_tar_with_dotslash_paths(archivers, request):
    """Test that paths starting with './' are normalized during import-tar."""
    archiver = request.getfixturevalue(archivers)
    # Create a simple directory structure
    create_regular_file(archiver.input_path, "dir/file")

    # Create a tar file with paths starting with './'
    with changedir("input"):
        # Directly use a path that starts with './'
        subprocess.check_call(["tar", "cf", "dotslash.tar", "./dir"])

        # Verify the tar file contains paths with './' prefix
        tar_content = subprocess.check_output(["tar", "tf", "dotslash.tar"]).decode()
        assert "./dir" in tar_content
        assert "./dir/file" in tar_content

    # Import the tar file into a Borg repository
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "import-tar", "dotslash", "input/dotslash.tar")

    # List the archive contents and verify no paths start with './'
    output = cmd(archiver, "list", "--format={path}{NL}", "dotslash")
    assert "./dir" not in output
    assert "dir" in output
    assert "dir/file" in output


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


@skipif_not_linux
@skipif_acls_not_working
def test_acl_roundtrip(archivers, request):
    """Test the complete workflow for POSIX ACLs with export-tar and import-tar.

    This test follows the workflow:
    1. set filesystem ACLs
    2. create a Borg archive
    3. export-tar this archive
    4. import-tar the resulting tar file
    5. extract the imported archive
    6. check the expected ACLs in the filesystem
    """
    archiver = request.getfixturevalue(archivers)

    # Define helper functions for working with ACLs
    def get_acl(path):
        item = {}
        acl_get(path, item, os.stat(path))
        return item

    def set_acl(path, access=None, default=None):
        item = {"acl_access": access, "acl_default": default}
        acl_set(path, item)

    # Define example ACLs
    ACCESS_ACL = b"user::rw-\nuser:root:rw-:0\ngroup::r--\ngroup:root:r--:0\nmask::rw-\nother::r--"
    DEFAULT_ACL = b"user::rw-\nuser:root:r--:0\ngroup::r--\ngroup:root:r--:0\nmask::rw-\nother::r--"

    # 1. Set filesystem ACLs
    # Create test files with ACLs
    create_regular_file(archiver.input_path, "file")
    os.mkdir(os.path.join(archiver.input_path, "dir"))

    file_path = os.path.join(archiver.input_path, "file")
    dir_path = os.path.join(archiver.input_path, "dir")

    # Set ACLs on the test files
    try:
        set_acl(file_path, access=ACCESS_ACL)
        set_acl(dir_path, access=ACCESS_ACL, default=DEFAULT_ACL)
    except OSError as e:
        pytest.skip(f"Failed to set ACLs: {e}")

    file_acl = get_acl(file_path)
    dir_acl = get_acl(dir_path)

    if not file_acl.get("acl_access") or not dir_acl.get("acl_access") or not dir_acl.get("acl_default"):
        pytest.skip("ACLs not supported or not working correctly")

    # 2. Create a Borg archive
    cmd(archiver, "repo-create", "--encryption=none")
    cmd(archiver, "create", "original", "input")

    # 3. export-tar this archive to a tar file
    cmd(archiver, "export-tar", "original", "acls.tar", "--tar-format=PAX")

    # 4. import-tar the resulting tar file
    cmd(archiver, "import-tar", "imported", "acls.tar")

    # 5. Extract the imported archive
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "imported")

        # 6. Check the expected ACLs in the filesystem
        extracted_file_path = os.path.abspath("input/file")
        extracted_dir_path = os.path.abspath("input/dir")

        extracted_file_acl = get_acl(extracted_file_path)
        extracted_dir_acl = get_acl(extracted_dir_path)

        # Check that access ACLs were preserved
        assert "acl_access" in extracted_file_acl
        assert extracted_file_acl["acl_access"] == file_acl["acl_access"]
        assert b"user:root:rw-" in file_acl["acl_access"]

        assert "acl_access" in extracted_dir_acl
        assert extracted_dir_acl["acl_access"] == dir_acl["acl_access"]
        assert b"user:root:rw-" in dir_acl["acl_access"]

        # Check that default ACLs were preserved for directories
        assert "acl_default" in extracted_dir_acl
        assert extracted_dir_acl["acl_default"] == dir_acl["acl_default"]
        assert b"user:root:r--" in dir_acl["acl_default"]
