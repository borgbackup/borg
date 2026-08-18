import io
import os
import random
import shutil
import subprocess
import sys
import tarfile

import pytest

from ... import xattr
from ...archiver.tar_cmds import chunks_to_sparse_info, gnu_sparse_10_map, SparseTarInfo
from ...archiver.tar_cmds import parse_sun_xattr_hdr, XATTR_HDRTYPE
from ...constants import *  # NOQA
from ...helpers import Error
from ...item import ChunkListEntry
from .. import changedir
from . import assert_dirs_equal, _extract_hardlinks_setup, cmd, requires_hardlinks, RK_ENCRYPTION
from . import create_test_files, create_regular_file
from . import generate_archiver_tests
from ...platform import acl_get, acl_set
from ..platform.platform_test import skipif_not_linux, skipif_acls_not_working

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local,binary")  # NOQA


def have_gnutar():
    if not shutil.which("tar"):
        return False
    popen = subprocess.Popen(["tar", "--version"], stdout=subprocess.PIPE)
    stdout, stderr = popen.communicate()
    return b"GNU tar" in stdout


requires_gnutar = pytest.mark.skipif(not have_gnutar(), reason="GNU tar must be installed for this test.")
requires_gzip = pytest.mark.skipif(not shutil.which("gzip"), reason="gzip must be installed for this test.")
requires_zstd = pytest.mark.skipif(not shutil.which("zstd"), reason="zstd must be installed for this test.")

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


@requires_gnutar
def test_export_tar(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "export-tar", "test", "simple.tar", "--progress", "--tar-format=GNU")
    with changedir("output"):
        # This probably assumes GNU tar. Note: use the -p switch to extract permissions regardless of umask.
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
    # --list's paths are those before processing with --strip-components
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
    create_test_files(archiver.input_path, create_hardlinks=False)  # hard links become separate files
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    with pytest.raises(ValueError, match="unexpected '..' element in path '../../../../etc/shadow'"):
        cmd(archiver, "import-tar", "dst", tar_archive, exit_code=2)


@requires_gzip
def test_import_tar_gz(archivers, request, tar_format="GNU"):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hard links become separate files
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "simple.tgz", f"--tar-format={tar_format}")
    cmd(archiver, "import-tar", "dst", "simple.tgz")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


@pytest.mark.parametrize("suffix", ["tar.zst", "tar.zstd", "tzst"])
def test_export_import_tar_zst(archivers, request, suffix):
    # zstd tarballs are (de)compressed in-process, no external zstd binary is needed.
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hard links become separate files
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", f"simple.{suffix}")
    with open(f"simple.{suffix}", "rb") as fd:
        assert fd.read(4) == ZSTD_MAGIC
    cmd(archiver, "import-tar", "dst", f"simple.{suffix}")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


def test_export_import_tar_zst_mt(archivers, request, monkeypatch):
    # exercise the multi-threaded compression path (nb_workers) of the in-process zstd filter.
    archiver = request.getfixturevalue(archivers)
    monkeypatch.setenv("BORG_ZSTD_MT_WORKERS", "2")
    monkeypatch.setattr("borg.compress._zstd_mt_workers", None)  # drop the cache
    create_test_files(archiver.input_path, create_hardlinks=False)  # hard links become separate files
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "simple.tar.zst")
    cmd(archiver, "import-tar", "dst", "simple.tar.zst")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


@requires_gnutar
@requires_zstd
def test_export_tar_zst_interop(archivers, request):
    # in-process zstd output must be readable by the standard zstd tool.
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path)
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    cmd(archiver, "export-tar", "test", "simple.tar.zst", "--tar-format=GNU")
    subprocess.check_call(["zstd", "-d", "simple.tar.zst", "-o", "simple.tar"])
    with changedir("output"):
        subprocess.check_call(["tar", "xpf", "../simple.tar", "--warning=no-timestamp"])
    assert_dirs_equal("input", "output/input", ignore_flags=True, ignore_xattrs=True, ignore_ns=True)


@requires_zstd
def test_tar_filter_zstd_external(archivers, request):
    # an explicit --tar-filter always runs the external filter program, also for zstd.
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hard links become separate files
    os.unlink("input/flagfile")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "simple.tar.zst", "--tar-filter=zstd")
    with open("simple.tar.zst", "rb") as fd:
        assert fd.read(4) == ZSTD_MAGIC
    cmd(archiver, "import-tar", "dst", "simple.tar.zst", "--tar-filter=zstd -d")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


@requires_gnutar
def test_import_concatenated_tar_with_ignore_zeros(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hard links become separate files
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

    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "import-tar", "--ignore-zeros", "dst", "input/concatenated.tar")
    # Clean up for assert_dirs_equal.
    os.unlink("input/concatenated.tar")

    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output", ignore_ns=True, ignore_xattrs=True)


@requires_gnutar
def test_import_concatenated_tar_without_ignore_zeros(archivers, request):
    archiver = request.getfixturevalue(archivers)
    create_test_files(archiver.input_path, create_hardlinks=False)  # hard links become separate files
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "src", "input")
    cmd(archiver, "export-tar", "src", "xattrs.tar", "--tar-format=PAX")
    cmd(archiver, "import-tar", "dst", "xattrs.tar")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
        extracted_path = os.path.abspath("input/file")
        xa_value_extracted = xattr.getxattr(extracted_path.encode(), xa_key)
    assert xa_value_extracted == xa_value


def _sparse_entries(sizes):
    return [ChunkListEntry(id=bytes([i]) * 32, size=size) for i, size in enumerate(sizes)]


def test_chunks_to_sparse_info():
    # no chunks / no holes: not sparse
    assert chunks_to_sparse_info([], []) is None
    assert chunks_to_sparse_info(_sparse_entries([512, 1024]), [False, False]) is None
    # a zero run shorter than a tar block cannot make a (block-aligned) hole
    assert chunks_to_sparse_info(_sparse_entries([512, 511, 512]), [False, True, False]) is None
    # leading hole; adjacent zero chunks coalesce into one hole
    chunks = _sparse_entries([1024, 512, 1536])
    map_entries, stream_plan, realsize = chunks_to_sparse_info(chunks, [True, True, False])
    assert map_entries == [(1536, 1536)]
    assert stream_plan == [chunks[2]]
    assert realsize == 3072
    # middle hole
    chunks = _sparse_entries([512, 1024, 1024, 512])
    map_entries, stream_plan, realsize = chunks_to_sparse_info(chunks, [False, True, True, False])
    assert map_entries == [(0, 512), (2560, 512)]
    assert stream_plan == [chunks[0], chunks[3]]
    assert realsize == 3072
    # trailing hole: terminating (realsize, 0) entry, like GNU tar creates it
    chunks = _sparse_entries([512, 1024])
    map_entries, stream_plan, realsize = chunks_to_sparse_info(chunks, [False, True])
    assert map_entries == [(0, 512), (1536, 0)]
    assert stream_plan == [chunks[0]]
    assert realsize == 1536
    # all-hole file (its trailing hole may end unaligned)
    chunks = _sparse_entries([512, 100])
    map_entries, stream_plan, realsize = chunks_to_sparse_info(chunks, [True, True])
    assert map_entries == [(612, 0)]
    assert stream_plan == []
    assert realsize == 612
    # holes shrink to whole 512-byte tar blocks (GNU tar's sparse reader needs block-aligned
    # data segments); the shaved-off zero bytes at the hole edges are emitted literally.
    chunks = _sparse_entries([10000, 40000, 10000])
    map_entries, stream_plan, realsize = chunks_to_sparse_info(chunks, [False, True, False])
    assert map_entries == [(0, 10240), (49664, 10336)]
    assert stream_plan == [chunks[0], 240, 336, chunks[2]]
    assert realsize == 60000
    # the stream plan produces exactly the data segments' bytes
    emitted = sum(entry if isinstance(entry, int) else entry.size for entry in stream_plan)
    assert emitted == sum(length for _, length in map_entries)


def test_gnu_sparse_10_map():
    # exactly the numbers/layout GNU tar writes, NUL-padded to a multiple of 512.
    map_bytes = gnu_sparse_10_map([(0, 1048576), (5242880, 1048576), (10485760, 0)])
    assert map_bytes == b"3\n0\n1048576\n5242880\n1048576\n10485760\n0\n" + b"\0" * (512 - 39)
    assert len(gnu_sparse_10_map([(1000, 0)])) == 512
    # a large map spills into multiple 512 byte blocks
    map_bytes = gnu_sparse_10_map([(i * 10000, 5000) for i in range(100)])
    assert len(map_bytes) % 512 == 0 and len(map_bytes) > 512
    numbers = [int(n) for n in map_bytes.rstrip(b"\0").split()]
    assert numbers[0] == 100 and numbers[1:3] == [0, 5000]


# chunkers used by the sparse tests: a fixed chunker (all-zero chunks exactly aligned with
# the zero runs) and a small-target fastcdc chunker (content-defined chunk boundaries, so the
# zero runs yield multiple repeated pure all-zero chunks of max. chunk size (64 KiB), possibly
# surrounded by mixed data/zeros chunks at the edges - like real sparse files chunked by the
# default chunker, just scaled down to small test files).
SPARSE_CHUNKER_FIXED = "--chunker-params=fixed,65536"
SPARSE_CHUNKER_CDC = "--chunker-params=fastcdc,12,16,14,2"  # 4 KiB min, 16 KiB target, 64 KiB max


def _create_sparse_test_input(input_path):
    """Create files containing runs of all-zero chunks (the files need not be sparse on disk)."""
    B = 65536  # the max. chunk size of the chunkers used by the sparse tests
    rnd = random.Random(42)  # pseudorandom data, so the cdc chunker cuts realistic chunks
    contents = {
        "sparse_img": rnd.randbytes(B) + b"\0" * (4 * B) + rnd.randbytes(B) + b"\0" * (4 * B),
        "allzero": b"\0" * (3 * B),
        "unaligned": b"\0" * (2 * B) + b"tail",  # leading hole, small unaligned trailing data chunk
        "dense": rnd.randbytes(B + 42),
        "empty": b"",
    }
    for name, data in contents.items():
        create_regular_file(input_path, name, contents=data)
    return contents


@pytest.mark.parametrize("chunker_params", [SPARSE_CHUNKER_FIXED, SPARSE_CHUNKER_CDC])
def test_export_tar_sparse(archivers, request, chunker_params):
    archiver = request.getfixturevalue(archivers)
    contents = _create_sparse_test_input(archiver.input_path)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", chunker_params, "test", "input")
    cmd(archiver, "export-tar", "test", "dense.tar")
    cmd(archiver, "export-tar", "--sparse", "test", "sparse.tar", "--progress")
    # storing the holes as sparse members must save space (~832 KiB of holes here)
    assert os.path.getsize("sparse.tar") < os.path.getsize("dense.tar") - 500000
    expected_sparse = {"input/sparse_img", "input/allzero", "input/unaligned"}
    seen = set()
    with tarfile.open("sparse.tar") as tar:
        for tarinfo in tar.getmembers():
            if not tarinfo.isreg():
                continue
            seen.add(tarinfo.name)
            # the tarinfo has the real (unmangled) name and the logical size,
            # and the member expands to the original content.
            name = tarinfo.name.rsplit("/", 1)[-1]
            assert tarinfo.size == len(contents[name])
            assert tar.extractfile(tarinfo).read() == contents[name]
            assert tarinfo.issparse() == (tarinfo.name in expected_sparse)
    assert seen == {"input/" + name for name in contents}


@pytest.mark.parametrize("chunker_params", [SPARSE_CHUNKER_FIXED, SPARSE_CHUNKER_CDC])
@pytest.mark.parametrize("tar_format", ["PAX", "BORG"])
def test_export_tar_sparse_roundtrip(archivers, request, tar_format, chunker_params):
    archiver = request.getfixturevalue(archivers)
    _create_sparse_test_input(archiver.input_path)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", chunker_params, "src", "input")
    cmd(archiver, "export-tar", "--sparse", f"--tar-format={tar_format}", "src", "sparse.tar")
    cmd(archiver, "import-tar", "dst", "sparse.tar")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


def test_export_tar_sparse_not_worthwhile(archivers, request):
    # when the sparse map would cost more space than the holes save, store a dense member.
    archiver = request.getfixturevalue(archivers)
    contents = b"X" * 448 + b"\0" * 64
    create_regular_file(archiver.input_path, "tinyhole", contents=contents)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "--chunker-params=fixed,64", "test", "input")
    cmd(archiver, "export-tar", "--sparse", "test", "sparse.tar")
    with tarfile.open("sparse.tar") as tar:
        tarinfo = tar.getmember("input/tinyhole")
        assert not tarinfo.issparse()
        assert tar.extractfile(tarinfo).read() == contents


@requires_gnutar
def test_export_tar_sparse_gnutar(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_sparse_test_input(archiver.input_path)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", SPARSE_CHUNKER_CDC, "test", "input")
    cmd(archiver, "export-tar", "--sparse", "test", "sparse.tar")
    with changedir("output"):
        subprocess.check_call(["tar", "xpf", "../sparse.tar", "--warning=no-timestamp"])
    assert_dirs_equal("input", "output/input", ignore_flags=True, ignore_xattrs=True, ignore_ns=True)
    if sys.platform == "linux":
        # GNU tar recreates the holes when extracting sparse members.
        st = os.stat("output/input/sparse_img")
        assert st.st_blocks * 512 < st.st_size


@requires_hardlinks
def test_export_tar_sparse_hardlinks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    contents = b"\0" * 2 * 65536 + b"data"
    create_regular_file(archiver.input_path, "sparse1", contents=contents)
    os.link(os.path.join(archiver.input_path, "sparse1"), os.path.join(archiver.input_path, "sparse2"))
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", SPARSE_CHUNKER_CDC, "src", "input")
    cmd(archiver, "export-tar", "--sparse", "src", "sparse.tar")
    with tarfile.open("sparse.tar") as tar:
        members = [ti for ti in tar.getmembers() if ti.name.startswith("input/sparse")]
        regs = [ti for ti in members if ti.isreg()]
        lnks = [ti for ti in members if ti.islnk()]
        assert len(regs) == 1 and len(lnks) == 1
        # the first occurrence carries the sparse content, the second one is a tar hard link
        # referencing the first one's real (unmangled) name.
        assert regs[0].issparse()
        assert tar.extractfile(regs[0]).read() == contents
        assert lnks[0].linkname == regs[0].name
    # roundtrip: as usual for import-tar, tar hard links become separate files (sharing chunks).
    cmd(archiver, "import-tar", "dst", "sparse.tar")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
        for name in "input/sparse1", "input/sparse2":
            with open(name, "rb") as f:
                assert f.read() == contents


def test_export_tar_sparse_strip_components(archivers, request):
    # the mangled member name and GNU.sparse.name must be based on the stripped path.
    archiver = request.getfixturevalue(archivers)
    contents = b"\0" * 2 * 65536 + b"end"
    create_regular_file(archiver.input_path, "dir/sparsefile", contents=contents)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", SPARSE_CHUNKER_CDC, "test", "input")
    cmd(archiver, "export-tar", "--sparse", "--strip-components=1", "test", "sparse.tar")
    with tarfile.open("sparse.tar") as tar:
        tarinfo = tar.getmember("dir/sparsefile")
        assert tarinfo.issparse()
        assert tar.extractfile(tarinfo).read() == contents


def test_sparse_tarinfo_base256_size():
    # a stored size beyond the 12-digit octal ustar field limit is base-256 encoded in the
    # ustar size field (with a correct checksum), and no pax "size" record is emitted
    # (sparse readers desync on such a record).
    tarinfo = SparseTarInfo(name="GNUSparseFile.0/big")
    tarinfo.size = 3 * 8**11  # 24 GiB of stored data, does not fit the octal field
    tarinfo.pax_headers = {"GNU.sparse.realsize": str(100 * 8**11)}
    buf = tarinfo.tobuf(tarfile.PAX_FORMAT, tarfile.ENCODING, "surrogateescape")
    assert b" size=" not in buf  # no pax "size" record (" realsize=" does not match)
    # frombuf validates the checksum and decodes the base-256 size field:
    parsed = tarfile.TarInfo.frombuf(buf[-tarfile.BLOCKSIZE :], tarfile.ENCODING, "surrogateescape")
    assert parsed.size == 3 * 8**11
    # small stored sizes keep the plain octal encoding:
    tarinfo.size = 4711
    buf = tarinfo.tobuf(tarfile.PAX_FORMAT, tarfile.ENCODING, "surrogateescape")
    assert buf[-tarfile.BLOCKSIZE :][124:136] == b"00000011147\x00"


def test_export_tar_sparse_base256_size(archivers, request, monkeypatch):
    # end-to-end wire-format test of the base-256 stored size: the encoding does not depend
    # on the value, so force it for small members instead of storing 8 GiB of data.
    archiver = request.getfixturevalue(archivers)
    if archiver.EXE:
        pytest.skip("monkeypatching does not reach a borg binary")
    monkeypatch.setattr(SparseTarInfo, "octal_size_limit", 1)
    contents = _create_sparse_test_input(archiver.input_path)
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", SPARSE_CHUNKER_CDC, "src", "input")
    cmd(archiver, "export-tar", "--sparse", "src", "sparse.tar")
    with tarfile.open("sparse.tar") as tar:
        for tarinfo in tar.getmembers():
            if tarinfo.isreg():
                name = tarinfo.name.rsplit("/", 1)[-1]
                assert tar.extractfile(tarinfo).read() == contents[name]
    if have_gnutar():
        with changedir("output"):
            subprocess.check_call(["tar", "xpf", "../sparse.tar", "--warning=no-timestamp"])
        assert_dirs_equal("input", "output/input", ignore_flags=True, ignore_xattrs=True, ignore_ns=True)
        shutil.rmtree("output/input")
    cmd(archiver, "import-tar", "dst", "sparse.tar")
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
    assert_dirs_equal("input", "output/input", ignore_ns=True, ignore_xattrs=True)


def test_export_tar_sparse_gnu_format_error(archivers, request):
    # --sparse requires a PAX-based tar format, the GNU format cannot store the sparse headers.
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file", contents=b"x")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "create", "test", "input")
    if archiver.FORK_DEFAULT:
        output = cmd(archiver, "export-tar", "--sparse", "--tar-format=GNU", "test", "out.tar", exit_code=2)
        assert "--sparse requires --tar-format" in output
    else:
        with pytest.raises(Error, match="--sparse requires --tar-format"):
            cmd(archiver, "export-tar", "--sparse", "--tar-format=GNU", "test", "out.tar")


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
    cmd(archiver, "repo-create", "--encryption=none-sha256")
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


def make_sun_xattr_hdr_payload(parent, attrpath, typeflag=b"0", link_names=None):
    """Byte-exact reimplementation of illumos tar's prepare_xattr(), see #8479."""
    # a "/" in attrpath separates an attribute of an attribute - stored as another NUL-separated segment
    names = parent + b"\x00" + attrpath.replace(b"/", b"\x00", 1) + b"\x00"
    complen = len(names) + 9  # 9 = sizeof(struct xattr_buf), incl. its 1 byte h_names placeholder
    if link_names:
        link = link_names[0] + b"\x00" + link_names[1] + b"\x00"
        linklen = len(link) + 9
    else:
        linklen = 0
    size = 37 + complen + linklen
    buf = bytearray(size)  # zero-filled, like the calloc() there
    buf[0:4] = b"1.0\x00"
    buf[7:17] = b"%09d\x00" % size
    buf[17:27] = b"%09d\x00" % complen
    buf[27:37] = b"%09d\x00" % linklen
    buf[37:44] = b"%06d\x00" % len(names)
    buf[44:45] = typeflag
    buf[45 : 45 + len(names)] = names
    if link_names:
        offset = 37 + complen
        buf[offset : offset + 7] = b"%06d\x00" % len(link)
        buf[offset + 7 : offset + 8] = typeflag
        buf[offset + 8 : offset + 8 + len(link)] = link
    return bytes(buf)


def add_tar_member(tar, name, type, content=b""):
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = type
    tarinfo.size = len(content)
    tarinfo.mode = 0o755 if type == tarfile.DIRTYPE else 0o644
    tarinfo.mtime = 1234567890
    tar.addfile(tarinfo, io.BytesIO(content) if content else None)


def add_sun_xattr_pair(tar, parent, attrname, value, typeflag=b"0", link_names=None, hdr_payload=None):
    # Solaris tar names xattr members with a decoy path, only the payloads matter.
    if hdr_payload is None:
        hdr_payload = make_sun_xattr_hdr_payload(parent, attrname, typeflag, link_names)
    decoy = (b"/dev/null/" + attrname).decode("utf-8", "surrogateescape")
    add_tar_member(tar, decoy + ".hdr", XATTR_HDRTYPE, hdr_payload)
    add_tar_member(tar, decoy, XATTR_HDRTYPE, value)


def exported_xattrs(archiver, name):
    """Return {path: {attr: value}} of all items with xattrs, platform-independently via a PAX export."""
    cmd(archiver, "export-tar", name, "xa.tar", "--tar-format=PAX")
    result = {}
    with tarfile.open("xa.tar") as tar:
        for tarinfo in tar:
            xa = {
                key.removeprefix("SCHILY.xattr.").encode("utf-8", "surrogateescape"): value.encode(
                    "utf-8", "surrogateescape"
                )
                for key, value in tarinfo.pax_headers.items()
                if key.startswith("SCHILY.xattr.")
            }
            if xa:
                result[tarinfo.name] = xa
    return result


def test_parse_sun_xattr_hdr():
    # header payloads captured from a real Solaris 10 tar archive (see #8479)
    payload_attr = (
        b"1.0\x00\x00\x00\x00000000076\x00000000039\x00000000000\x00000030\x000SolarisMetadata\x00ANewAttribute\x00\x00"
    )
    assert parse_sun_xattr_hdr(payload_attr) == (b"0", [b"SolarisMetadata", b"ANewAttribute"], False)
    assert make_sun_xattr_hdr_payload(b"SolarisMetadata", b"ANewAttribute") == payload_attr
    payload_attrdir = (
        b"1.0\x00\x00\x00\x00000000064\x00000000027\x00000000000\x00000018\x005SolarisMetadata\x00.\x00\x00"
    )
    assert parse_sun_xattr_hdr(payload_attrdir) == (b"5", [b"SolarisMetadata", b"."], False)
    linked = make_sun_xattr_hdr_payload(b"file1", b"attr1", link_names=(b"file0", b"attr0"))
    assert parse_sun_xattr_hdr(linked) == (b"0", [b"file1", b"attr1"], True)
    assert parse_sun_xattr_hdr(b"") is None
    assert parse_sun_xattr_hdr(b"\xfd\xff\x32\x00" + b"\x40" * 50) is None  # IBM i pax style payload
    assert parse_sun_xattr_hdr(payload_attr[:-10]) is None  # truncated (h_size mismatch)


def test_import_tar_solaris_xattrs(archivers, request):
    archiver = request.getfixturevalue(archivers)
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "file1", tarfile.REGTYPE, b"data1")
        add_sun_xattr_pair(tar, b"file1", b".", b"", typeflag=b"5")  # the hidden attr directory itself
        add_sun_xattr_pair(tar, b"file1", b"SUNWattr_ro", b"sysattr stuff")  # system attr
        add_sun_xattr_pair(tar, b"file1", b"attr1", b"value1")
        add_sun_xattr_pair(tar, b"file1", b"attr2", b"not valid utf-8: \xff")
        add_tar_member(tar, "file2", tarfile.REGTYPE, b"data2")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    output = cmd(archiver, "import-tar", "dst", "sun.tar")
    assert "skipped" not in output
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {"file1", "file2"}
    assert exported_xattrs(archiver, "dst") == {"file1": {b"attr1": b"value1", b"attr2": b"not valid utf-8: \xff"}}


def test_import_tar_solaris_xattrs_dir(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # a directory's xattr members only arrive after the directory's whole subtree
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "dir", tarfile.DIRTYPE)
        add_tar_member(tar, "dir/sub", tarfile.DIRTYPE)
        add_tar_member(tar, "dir/sub/file", tarfile.REGTYPE, b"data")
        add_sun_xattr_pair(tar, b"dir/sub/file", b"fattr", b"fvalue")
        add_sun_xattr_pair(tar, b"dir/sub", b"sattr", b"svalue")
        add_sun_xattr_pair(tar, b"dir", b"dattr", b"dvalue")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "import-tar", "dst", "sun.tar")
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {"dir", "dir/sub", "dir/sub/file"}
    assert exported_xattrs(archiver, "dst") == {
        "dir": {b"dattr": b"dvalue"},
        "dir/sub": {b"sattr": b"svalue"},
        "dir/sub/file": {b"fattr": b"fvalue"},
    }


def test_import_tar_solaris_xattrs_root_dir(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # "tar cf x ." style archive: the root member "./" becomes item path ".", its xattrs arrive last
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "./", tarfile.DIRTYPE)
        add_tar_member(tar, "./file", tarfile.REGTYPE, b"data")
        add_sun_xattr_pair(tar, b".", b"rootattr", b"rootvalue")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "import-tar", "dst", "sun.tar")
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {".", "file"}
    assert exported_xattrs(archiver, "dst") == {".": {b"rootattr": b"rootvalue"}}


def test_import_tar_solaris_xattrs_nonascii(archivers, request):
    archiver = request.getfixturevalue(archivers)
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "fö", tarfile.REGTYPE, b"data")
        add_sun_xattr_pair(tar, "fö".encode(), "ättr".encode(), b"value")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    cmd(archiver, "import-tar", "dst", "sun.tar")
    assert exported_xattrs(archiver, "dst") == {"fö": {"ättr".encode(): b"value"}}


def test_import_tar_solaris_xattrs_skipped(archivers, request):
    archiver = request.getfixturevalue(archivers)
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "file1", tarfile.REGTYPE, b"data1")
        # hard-linked attribute
        add_sun_xattr_pair(tar, b"file1", b"lattr", b"", link_names=(b"file0", b"attr0"))
        # attribute of an attribute (three name segments)
        add_sun_xattr_pair(tar, b"file1", b"attr1/nested", b"v")
        # hostile header: "/" kept inside the attribute name instead of segment splitting
        unsplit = make_sun_xattr_hdr_payload(b"file1", b"attrX?nested").replace(b"?", b"/")
        add_sun_xattr_pair(tar, b"file1", b"attrX", b"v", hdr_payload=unsplit)
        # unsafe parent path
        add_sun_xattr_pair(tar, b"../evil", b"attr2", b"v")
        # parent path not in the archive (anymore)
        add_sun_xattr_pair(tar, b"nosuchfile", b"attr3", b"v")
        add_tar_member(tar, "file2", tarfile.REGTYPE, b"data2")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    output = cmd(archiver, "import-tar", "dst", "sun.tar", exit_code=1)
    assert "skipped hard-linked Solaris extended attributes (unsupported) (1 members)" in output
    assert "skipped Solaris extended attributes of extended attributes (unsupported) (2 members)" in output
    assert "skipped Solaris extended attributes with an unsafe parent path (1 members)" in output
    assert "skipped Solaris extended attributes without a parent item (1 members)" in output
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {"file1", "file2"}
    assert exported_xattrs(archiver, "dst") == {}


def test_import_tar_type_E_fallback(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # IBM i pax also uses tarinfo type b'E', but with a proprietary payload - and no pairing,
    # so each member must be skipped on its own, without lookahead.
    with tarfile.open("ibmi.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "file1", tarfile.REGTYPE, b"data1")
        add_tar_member(tar, ".SUBJECT", XATTR_HDRTYPE, b"\xfd\xff\x32\x00" + b"\x40" * 50)
        add_tar_member(tar, ".CODEPAGE", XATTR_HDRTYPE, b"\xfe\xff\x02\x00\x11\x01")
        add_tar_member(tar, "file2", tarfile.REGTYPE, b"data2")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    output = cmd(archiver, "import-tar", "dst", "ibmi.tar", "--list", exit_code=1)
    assert "skipped unrecognized extended attribute members (tarinfo type b'E') (2 members)" in output
    assert "E .SUBJECT" in output
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {"file1", "file2"}


def test_import_tar_solaris_xattr_hdr_at_eof(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # a lone xattr header member at the end of the tar must not crash the import
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "file1", tarfile.REGTYPE, b"data1")
        add_tar_member(tar, "/dev/null/attr1.hdr", XATTR_HDRTYPE, make_sun_xattr_hdr_payload(b"file1", b"attr1"))
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    output = cmd(archiver, "import-tar", "dst", "sun.tar", exit_code=1)
    assert "skipped Solaris extended attribute headers without a value member (1 members)" in output
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {"file1"}


def test_import_tar_solaris_xattr_hdr_mispaired(archivers, request):
    archiver = request.getfixturevalue(archivers)
    # an xattr header member followed by a regular member: the regular member must not get lost
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "file1", tarfile.REGTYPE, b"data1")
        add_tar_member(tar, "/dev/null/attr1.hdr", XATTR_HDRTYPE, make_sun_xattr_hdr_payload(b"file1", b"attr1"))
        add_tar_member(tar, "file2", tarfile.REGTYPE, b"data2")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    output = cmd(archiver, "import-tar", "dst", "sun.tar", exit_code=1)
    assert "skipped Solaris extended attribute headers without a value member (1 members)" in output
    files = cmd(archiver, "list", "dst", "--format", "{path}{NL}").splitlines()
    assert set(files) == {"file1", "file2"}
    with changedir(archiver.output_path):
        cmd(archiver, "extract", "dst")
        with open("file2", "rb") as f:
            assert f.read() == b"data2"


def test_import_tar_solaris_xattr_value_too_big(archivers, request):
    archiver = request.getfixturevalue(archivers)
    with tarfile.open("sun.tar", "w", format=tarfile.USTAR_FORMAT) as tar:
        add_tar_member(tar, "file1", tarfile.REGTYPE, b"data1")
        add_sun_xattr_pair(tar, b"file1", b"big", b"\x00" * (2**24 + 1))
        add_sun_xattr_pair(tar, b"file1", b"attr1", b"value1")
    cmd(archiver, "repo-create", "--encryption=none-sha256")
    output = cmd(archiver, "import-tar", "dst", "sun.tar", exit_code=1)
    assert "skipped too big Solaris extended attribute values (1 members)" in output
    assert exported_xattrs(archiver, "dst") == {"file1": {b"attr1": b"value1"}}
