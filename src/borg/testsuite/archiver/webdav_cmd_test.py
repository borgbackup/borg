# This file tests the webdav command (read-only HTTP serving of archive contents).
# The server is started in-process (no borg CLI invocation for the serving part),
# so these tests run without any optional dependency.

import http.client
import io
import os
import signal
import socket
import stat
import tarfile
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from ...constants import *  # NOQA
from ...manifest import Manifest
from ...platform import is_win32
from ...repository import Repository
from ...webdav import make_server
from .. import are_symlinks_supported, are_hardlinks_supported
from . import RK_ENCRYPTION, cmd, create_regular_file, generate_archiver_tests

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA

# a file name that exercises HTML escaping and URL encoding. It contains characters
# (< > and, for the injection test below, CR/LF) that are illegal in Windows file
# names, so files with such names can only be created (and thus tested) on non-Windows.
FUNNY_NAME = "a <b>&c ä.txt"

# a non-ASCII file name that is legal on every platform (including Windows), so the
# percent-encoding of non-ASCII names is exercised everywhere - "grüße.txt" url-encodes
# to "gr%C3%BC%C3%9Fe.txt" (ü -> %C3%BC, ß -> %C3%9F).
UNICODE_NAME = "grüße.txt"
UNICODE_NAME_ENC = "gr%C3%BC%C3%9Fe.txt"


def _create_archive(archiver):
    create_regular_file(archiver.input_path, "file1", contents=b"data1")
    create_regular_file(archiver.input_path, "subdir/file2", contents=b"subdir data")
    create_regular_file(archiver.input_path, UNICODE_NAME, contents=b"unicode data")
    if not is_win32:
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
        # the heading is a breadcrumb: parent segments link to their directory, but the
        # last segment (the current directory) is plain text. It is followed by an icon
        # link to download the directory as a tar archive.
        assert '<h1><a href="/test/">test</a>/input/<a class="dl" href="?tar=1"' in page
        # a non-ASCII (but everywhere-legal) name is percent-encoded in the link, shown as-is in text
        assert f'<a href="{UNICODE_NAME_ENC}">{UNICODE_NAME}</a>' in page
        # funny file name is html-escaped in text and percent-encoded in the link
        if not is_win32:
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
        # a non-ASCII name (legal on all platforms) round-trips via its percent-encoded url
        status, _, body = get(f"{base_url}/test/input/{UNICODE_NAME_ENC}")
        assert status == 200
        assert body == b"unicode data"
        # a file with a percent-encoded url (its name has html/url-special characters)
        if not is_win32:
            status, headers, body = get(base_url + "/test/input/a%20%3Cb%3E%26c%20%C3%A4.txt")
            assert status == 200
            assert body == b"funny data"
            assert headers["Content-Type"].startswith("text/plain")


def _get_tar(url):
    """GET a ?tar download and return (headers, tarfile.TarFile opened on the body)."""
    status, headers, body = get(url)
    assert status == 200
    assert headers["Content-Type"] == "application/x-tar"
    # the size is not known in advance, so the tar is streamed with chunked encoding
    assert headers.get("Transfer-Encoding") == "chunked"
    assert "Content-Length" not in headers
    tar = tarfile.open(fileobj=io.BytesIO(body), mode="r")  # raises if the tar is malformed/truncated
    return headers, tar


def test_webdav_tar(archivers, request):
    archiver = request.getfixturevalue(archivers)
    big = _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        headers, tar = _get_tar(base_url + "/test/input/?tar=1")
        # the download is offered as a .tar attachment named after the directory
        assert 'filename="input.tar"' in headers["Content-Disposition"]
        members = {m.name: m for m in tar.getmembers()}
        # the tree is rooted at the requested directory ("input"), with its full contents
        assert tar.extractfile("input/file1").read() == b"data1"
        assert tar.extractfile("input/big").read() == big  # multi-chunk file, streamed + padded
        assert tar.extractfile("input/subdir/file2").read() == b"subdir data"
        assert tar.extractfile("input/" + UNICODE_NAME).read() == b"unicode data"
        # unlike a plain file download, the tar preserves POSIX metadata: directories,
        # sub-second mtime, owner/mode and - shown here - symlinks and hard links.
        assert members["input/subdir"].isdir()
        assert members["input/file1"].mode == stat.S_IMODE(os.stat(os.path.join(archiver.input_path, "file1")).st_mode)
        if are_symlinks_supported():
            assert members["input/link1"].issym()
            assert members["input/link1"].linkname == "somewhere/else"
        if are_hardlinks_supported():
            # the hard link pair appears once as a regular file and once as a tar hard link,
            # both resolving to the same content.
            assert tar.extractfile("input/hardlink").read() == b"data1"
            assert {members["input/file1"].type, members["input/hardlink"].type} == {tarfile.REGTYPE, tarfile.LNKTYPE}


def test_webdav_tar_subdir_and_head(archivers, request):
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    with webdav_server(archiver) as base_url:
        # a tar of a nested directory is rooted at that directory (paths stripped above it)
        headers, tar = _get_tar(base_url + "/test/input/subdir/?tar=1")
        assert 'filename="subdir.tar"' in headers["Content-Disposition"]
        names = tar.getnames()
        assert "subdir" in names and "subdir/file2" in names
        assert not any(n.startswith("input/") for n in names)  # the "input/" prefix is stripped
        # a HEAD request returns the tar headers but no body
        status, headers, body = http_request(base_url + "/test/input/subdir/?tar=1", "HEAD")
        assert status == 200
        assert headers["Content-Type"] == "application/x-tar"
        assert body == b""
        # ?tar at the archive root exports the whole archive (no path prefix stripped)
        _, tar = _get_tar(base_url + "/test/?tar=1")
        assert "input/file1" in tar.getnames()
        # a directory tar URL without the trailing slash redirects but keeps the query
        # string, so the (urllib-followed) redirect still delivers the tar, not the listing
        _, tar = _get_tar(base_url + "/test/input?tar=1")
        assert "input/file1" in tar.getnames()


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
        # a symlink is shown in listings but is not downloadable via GET
        if are_symlinks_supported():
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                get(base_url + "/test/input/link1")
            assert exc_info.value.code == 403
        # a PROPFIND body larger than 1 MiB is rejected: the server checks Content-Length
        # and answers 413 without reading the oversized body.
        conn = http.client.HTTPConnection(urlsplit(base_url).netloc)
        try:
            conn.putrequest("PROPFIND", "/test/input/file1", skip_accept_encoding=True)
            conn.putheader("Depth", "0")
            conn.putheader("Content-Length", str(1024 * 1024 + 1))
            conn.endheaders()
            conn.send(b"x")  # only a token byte; the header alone triggers the rejection
            assert conn.getresponse().status == 413
        finally:
            conn.close()


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
        # a non-ASCII name is percent-encoded in the PROPFIND href on all platforms
        assert f"/test/input/{UNICODE_NAME_ENC}" in hrefs
        if not is_win32:
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
        # bodies containing a DTD are rejected (entity expansion / "XML bomb" defense)
        bomb = (
            b'<?xml version="1.0"?><!DOCTYPE b [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            b'<D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&b;</D:displayname></D:prop></D:propfind>'
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            propfind(base_url + "/test/input/file1", depth="0", body=bomb)
        assert exc_info.value.code == 400
        # the DTD rejection is encoding-proof: a UTF-16 encoded DTD (whose bytes do
        # not contain the ascii "<!DOCTYPE") must be rejected, too
        utf16_bomb = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE b [<!ENTITY a "aaaaaaaaaa">]>'
            '<D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&a;</D:displayname></D:prop></D:propfind>'
        ).encode("utf-16")
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            propfind(base_url + "/test/input/file1", depth="0", body=utf16_bomb)
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


@pytest.mark.skipif(is_win32, reason="cannot create files with CR/LF in the name on Windows")
def test_webdav_header_injection(archivers, request):
    # File/directory names from an archive may contain CR/LF - names like
    # "x\r\nEvil-Header: 1" must not be able to inject headers into responses
    # that echo the name (Content-Disposition, Location), see CodeQL
    # py/http-response-splitting and the OWASP article on response splitting.
    archiver = request.getfixturevalue(archivers)
    evil_file = "inj\r\nEvil-Header: 1"
    evil_dir = "dir\r\nEvil-Header: 2"
    create_regular_file(archiver.input_path, evil_file, contents=b"gotcha")
    create_regular_file(archiver.input_path, evil_dir + "/inner", contents=b"inner")
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    with webdav_server(archiver) as base_url:
        host_port = urlsplit(base_url).netloc
        # downloading the evil file: Content-Disposition must be sanitized
        status, headers, body = get(f"{base_url}/test/input/inj%0D%0AEvil-Header%3A%201")
        assert status == 200
        assert body == b"gotcha"
        assert "Evil-Header" not in headers
        assert 'filename="inj__Evil-Header: 1"' in headers["Content-Disposition"]
        assert "%0D%0A" in headers["Content-Disposition"]  # RFC 8187 encoded form
        # a tar download of the evil directory: its name feeds Content-Disposition, which
        # must be sanitized too (the directory name becomes the tar file name).
        status, headers, _ = get(f"{base_url}/test/input/dir%0D%0AEvil-Header%3A%202/?tar=1")
        assert status == 200
        assert "Evil-Header" not in headers
        assert 'filename="dir__Evil-Header: 2.tar"' in headers["Content-Disposition"]
        # the directory redirect: Location must be percent-encoded, no header injected
        # (plain http.client here, so the 301 is not followed)
        conn = http.client.HTTPConnection(host_port)
        try:
            conn.request("GET", "/test/input/dir%0D%0AEvil-Header%3A%202")
            response = conn.getresponse()
            assert response.status == 301
            assert response.getheader("Evil-Header") is None
            assert response.getheader("Location") == "/test/input/dir%0D%0AEvil-Header%3A%202/"
        finally:
            conn.close()


def test_webdav_data_cache(archivers, request, monkeypatch):
    # decrypted chunks are cached across requests, sized by BORG_MOUNT_DATA_CACHE_ENTRIES.
    monkeypatch.setenv("BORG_MOUNT_DATA_CACHE_ENTRIES", "8")
    archiver = request.getfixturevalue(archivers)
    big = _create_archive(archiver)
    args = SimpleNamespace(
        sort_by="ts", match_archives=None, first=None, last=None, older=None, newer=None, oldest=None, newest=None
    )
    repository = Repository(archiver.repository_path, exclusive=True)
    with repository:
        manifest = Manifest.load(repository, Manifest.NO_OPERATION_CHECK)
        server = make_server(manifest, args, port=0)
        assert server.data_cache._capacity == 8  # the env var is honored
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/test/input/big"
            assert len(server.data_cache) == 0
            status, _, body = get(url)  # first read populates the cache
            assert status == 200 and body == big
            assert len(server.data_cache) > 0  # the multi-chunk file cached some chunks
            # a second (ranged) read hits the cache and must return identical bytes
            status, _, body = get(url, headers={"Range": "bytes=0-99"})
            assert status == 206 and body == big[:100]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)


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


@pytest.mark.skipif(is_win32 or not hasattr(os, "mkfifo"), reason="fifo (a special file) needs POSIX")
def test_webdav_special_files(archivers, request):
    # A named pipe stands in for special files (devices, fifos, sockets): it is shown in
    # browser listings but not downloadable and not exposed via WebDAV - yet a tar download
    # (which preserves metadata) does include it.
    archiver = request.getfixturevalue(archivers)
    create_regular_file(archiver.input_path, "file1", contents=b"data1")
    os.mkfifo(os.path.join(archiver.input_path, "pipe"))
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    cmd(archiver, "create", "test", "input")
    with webdav_server(archiver) as base_url:
        # shown in the listing, but as plain text (not a download link)
        status, _, body = get(base_url + "/test/input/")
        assert status == 200
        page = body.decode("utf-8")
        assert "pipe" in page
        assert 'href="pipe"' not in page
        # a GET on it is refused (it is not a regular file)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            get(base_url + "/test/input/pipe")
        assert exc_info.value.code == 403
        # not exposed via WebDAV (the protocol has no concept of a fifo)
        _, _, xml_body = propfind(base_url + "/test/input/", depth="1")
        assert not any("pipe" in href for href in propfind_hrefs(xml_body))
        # but included in a tar download, as a fifo entry
        _, tar = _get_tar(base_url + "/test/input/?tar=1")
        assert tar.getmember("input/pipe").isfifo()


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(is_win32, reason="uses a POSIX signal to stop the foreground server")
def test_webdav_command_serves_and_stops(archivers, request):
    # exercise the actual `borg webdav` command (in the foreground): it must serve requests
    # and, on SIGTERM, shut down cleanly and release the repository lock.
    archiver = request.getfixturevalue(archivers)
    _create_archive(archiver)
    port = _free_port()
    served = []

    def client_then_stop():
        base = f"http://127.0.0.1:{port}/"
        for _ in range(100):  # wait until the server is up (do_webdav installs its handler by then)
            try:
                with urllib.request.urlopen(base) as response:
                    served.append(response.status)
                    break
            except OSError:
                time.sleep(0.1)
        time.sleep(0.2)  # small margin so the SIGTERM handler is surely installed
        os.kill(os.getpid(), signal.SIGTERM)  # ask the foreground server to stop

    stopper = threading.Thread(target=client_then_stop, daemon=True)
    stopper.start()
    cmd(archiver, "webdav", "--foreground", "--port", str(port))  # blocks until stopped
    stopper.join(timeout=10)
    assert served == [200]  # the command actually served a request
    # the repository lock was released on shutdown, so a following borg command still works
    cmd(archiver, "repo-info")
