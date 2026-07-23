# This file tests the webdav command (read-only HTTP serving of archive contents).
# The server is started in-process (no borg CLI invocation for the serving part),
# so these tests run without any optional dependency.

import os
import threading
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
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


def get(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request) as response:
        return response.status, dict(response.headers), response.read()


def http_request(url, method, headers=None, body=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    with urllib.request.urlopen(req) as response:
        return response.status, dict(response.headers), response.read()


def propfind(url, depth="1", body=None):
    return http_request(url, "PROPFIND", headers={"Depth": depth}, body=body)


def propfind_hrefs(xml):
    """Parse a multistatus document, return {href: response element}."""
    tree = ET.fromstring(xml)
    assert tree.tag == "{DAV:}multistatus"
    return {resp.find("{DAV:}href").text: resp for resp in tree.findall("{DAV:}response")}


def prop_of(response, tag, status="200 OK"):
    """Return the property element *tag* from the propstat with *status*, or None."""
    for propstat in response.findall("{DAV:}propstat"):
        if propstat.find("{DAV:}status").text.endswith(status):
            elem = propstat.find(f"{{DAV:}}prop/{tag}")
            if elem is not None:
                return elem
    return None


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
        # writing/locking WebDAV methods are rejected, too
        for method in "PUT", "MKCOL", "LOCK", "PROPPATCH":
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                http_request(base_url + "/test/input/file1", method)
            assert exc_info.value.code == 405
            assert "PROPFIND" in exc_info.value.headers["Allow"]


def test_webdav_options(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        status, headers, _ = http_request(base_url + "/", "OPTIONS")
        assert status == 200
        assert headers["DAV"] == "1"
        assert "PROPFIND" in headers["Allow"]


def test_webdav_propfind(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        # depth 0 on a file: exactly one response with the file's properties
        status, headers, body = propfind(base_url + "/test/input/file1", depth="0")
        assert status == 207
        assert headers["Content-Type"].startswith("application/xml")
        hrefs = propfind_hrefs(body)
        assert list(hrefs) == ["/test/input/file1"]
        response = hrefs["/test/input/file1"]
        assert prop_of(response, "{DAV:}getcontentlength").text == "5"
        assert prop_of(response, "{DAV:}resourcetype").find("{DAV:}collection") is None
        assert prop_of(response, "{DAV:}getetag").text.startswith('"')
        assert "GMT" in prop_of(response, "{DAV:}getlastmodified").text
        # depth 1 on a directory: the directory itself and its children
        status, _, body = propfind(base_url + "/test/input/", depth="1")
        hrefs = propfind_hrefs(body)
        assert "/test/input/" in hrefs
        assert "/test/input/subdir/" in hrefs
        assert "/test/input/file1" in hrefs
        assert "/test/input/a%20%3Cb%3E%26c%20%C3%A4.txt" in hrefs
        assert prop_of(hrefs["/test/input/subdir/"], "{DAV:}resourcetype").find("{DAV:}collection") is not None
        # symlinks are not exposed via WebDAV
        assert not any("link1" in href for href in hrefs)
        # depth 1 on the server root: archives are listed as collections
        status, _, body = propfind(base_url + "/", depth="1")
        hrefs = propfind_hrefs(body)
        assert "/" in hrefs and "/test/" in hrefs
        assert prop_of(hrefs["/test/"], "{DAV:}resourcetype").find("{DAV:}collection") is not None


def test_webdav_propfind_body(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        # a named-prop request returns the known prop with 200 and the unknown one with 404
        body = (
            b'<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop>'
            b"<D:getcontentlength/><D:nosuchprop/>"
            b"</D:prop></D:propfind>"
        )
        status, _, result = propfind(base_url + "/test/input/file1", depth="0", body=body)
        assert status == 207
        response = propfind_hrefs(result)["/test/input/file1"]
        assert prop_of(response, "{DAV:}getcontentlength").text == "5"
        assert prop_of(response, "{DAV:}nosuchprop", status="404 Not Found") is not None
        # garbage body -> 400
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            propfind(base_url + "/test/input/file1", depth="0", body=b"<not-propfind/>")
        assert exc_info.value.code == 400
        # depth infinity is refused
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            propfind(base_url + "/test/input/", depth="infinity")
        assert exc_info.value.code == 403
        # PROPFIND on a symlink or a missing path -> 404
        for path in "/test/input/link1", "/test/input/no-such-file":
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                propfind(base_url + path, depth="0")
            assert exc_info.value.code == 404


def test_webdav_ranges(archivers, request):
    archiver = request.getfixturevalue(archivers)
    big = _create_archive(archiver)
    size = len(big)
    with webdav_server(archiver) as base_url:
        url = base_url + "/test/input/big"
        # a range within the first chunk
        status, headers, body = get(url, headers={"Range": "bytes=10-99"})
        assert status == 206
        assert body == big[10:100]
        assert headers["Content-Range"] == f"bytes 10-99/{size}"
        assert headers["Content-Length"] == "90"
        # a range spanning chunk boundaries, somewhere in the middle
        start, end = size // 2 - 1000, size // 2 + 1000
        status, headers, body = get(url, headers={"Range": f"bytes={start}-{end}"})
        assert status == 206
        assert body == big[start : end + 1]
        # an open-ended range and a suffix range
        status, _, body = get(url, headers={"Range": f"bytes={size - 10}-"})
        assert status == 206 and body == big[-10:]
        status, _, body = get(url, headers={"Range": "bytes=-10"})
        assert status == 206 and body == big[-10:]
        # an unsatisfiable range
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            get(url, headers={"Range": f"bytes={size}-"})
        assert exc_info.value.code == 416
        assert exc_info.value.headers["Content-Range"] == f"bytes */{size}"


def test_webdav_conditional_get(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        url = base_url + "/test/input/file1"
        status, headers, _ = get(url)
        assert status == 200
        etag = headers["ETag"]
        assert headers["Accept-Ranges"] == "bytes"
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            get(url, headers={"If-None-Match": etag})
        assert exc_info.value.code == 304
        # a non-matching etag serves the content normally
        status, _, body = get(url, headers={"If-None-Match": '"different"'})
        assert status == 200 and body == b"data1"
