# This file tests the webdav command (read-only HTTP serving of archive contents).
# The server is started in-process (no borg CLI invocation for the serving part),
# so these tests run without any optional dependency.

import os
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from ...constants import *  # NOQA
from ...manifest import Manifest
from ...repository import Repository
from ...webdav import make_server
from .. import are_symlinks_supported, are_hardlinks_supported
from . import RK_ENCRYPTION, cmd, create_regular_file, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA

FUNNY_NAME = "a <b>&c ä.txt"


def _create_archive(archiver):
    create_regular_file(archiver.input_path, "file1", contents=b"data1")
    create_regular_file(archiver.input_path, "subdir/file2", contents=b"subdir data")
    create_regular_file(archiver.input_path, FUNNY_NAME, contents=b"funny data")
    big = os.urandom(5 * 1024 * 1024)  # big enough for multiple chunks with default chunker params
    create_regular_file(archiver.input_path, "big", contents=big)
    if are_symlinks_supported():
        os.symlink("somewhere/else", os.path.join(archiver.input_path, "link1"))
    if are_hardlinks_supported():
        os.link(os.path.join(archiver.input_path, "file1"), os.path.join(archiver.input_path, "hardlink"))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    return big


@contextmanager
def webdav_server(archiver):
    """Start the webdav server in-process on an ephemeral localhost port."""
    args = SimpleNamespace(
        sort_by="ts", match_archives=None, first=None, last=None, older=None, newer=None, oldest=None, newest=None
    )
    repository = Repository(archiver.repository_path, exclusive=True)
    with repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        server = make_server(manifest, args, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)


def get(url):
    with urllib.request.urlopen(url) as response:
        return response.status, dict(response.headers), response.read()


def test_webdav_browse(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        # root: archive list
        status, headers, body = get(base_url + "/")
        assert status == 200
        assert headers["Content-Type"] == "text/html; charset=utf-8"
        page = body.decode("utf-8")
        assert '<a href="test/">test/</a>' in page
        # missing trailing slash on a directory redirects (followed by urllib)
        status, _, body = get(base_url + "/test/input")
        assert status == 200
        page = body.decode("utf-8")
        assert '<a href="file1">file1</a>' in page
        assert '<a href="subdir/">subdir/</a>' in page
        # precise sizes in bytes, with dots as thousands separators
        assert ">5.242.880<" in page
        # funny file name is html-escaped in text and percent-encoded in the link
        assert "a &lt;b&gt;&amp;c ä.txt" in page
        assert 'href="a%20%3Cb%3E%26c%20%C3%A4.txt"' in page
        if are_symlinks_supported():
            assert "link1 -&gt; somewhere/else" in page
            assert 'href="link1"' not in page  # symlinks are not downloadable


def test_webdav_download(archivers, request):
    archiver = request.getfixturevalue(archivers)
    big = _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        status, headers, body = get(base_url + "/test/input/file1")
        assert status == 200
        assert body == b"data1"
        assert headers["Content-Length"] == "5"
        assert "GMT" in headers["Last-Modified"]
        assert headers["Content-Type"] == "application/octet-stream"  # no file extension
        # multi-chunk file round-trips intact
        status, headers, body = get(base_url + "/test/input/big")
        assert status == 200
        assert body == big
        assert headers["Content-Length"] == str(len(big))
        # a file in a subdirectory, with a percent-encoded url
        status, headers, body = get(base_url + "/test/input/a%20%3Cb%3E%26c%20%C3%A4.txt")
        assert status == 200
        assert body == b"funny data"
        assert headers["Content-Type"].startswith("text/plain")


@pytest.mark.skipif(not are_hardlinks_supported(), reason="hardlinks not supported")
def test_webdav_hardlinks(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        # each hardlinked regular file item has its own chunks list, so both must serve content
        for name in "file1", "hardlink":
            status, _, body = get(f"{base_url}/test/input/{name}")
            assert status == 200
            assert body == b"data1"


def test_webdav_errors(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            get(base_url + "/no-such-archive/")
        assert exc_info.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            get(base_url + "/test/input/no-such-file")
        assert exc_info.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            get(base_url + "/test/input/../input/file1")
        assert exc_info.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(urllib.request.Request(base_url + "/", method="POST"))
        assert exc_info.value.code == 405
