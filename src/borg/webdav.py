"""Read-only WebDAV / HTTP server providing access to archive contents (``borg webdav``).

Web browsers get HTML directory listings and file downloads (GET/HEAD, incl.
Range requests and conditional requests). WebDAV clients (class 1: OPTIONS,
PROPFIND) can mount the served archives as a read-only network file system -
such clients are built into Windows Explorer, macOS Finder, the common Linux
file managers (gvfs/KIO) and davfs2. All methods that would modify something
(PUT, DELETE, PROPPATCH, MKCOL, COPY, MOVE, LOCK, ...) are rejected.

This module only uses the Python standard library, so it works without any
optional dependencies.
"""

import html
import mimetypes
import re
import stat
import tarfile
import threading
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple
from urllib.parse import parse_qs, quote, unquote_to_bytes
from xml.etree import ElementTree as ET  # nosec B405 # only used to *build* response XML, never to parse input
from xml.parsers import expat

from . import __version__
from .archive import Archive
from .constants import *  # NOQA
from .helpers import remove_surrogates, HardLinkManager
from .logger import create_logger
from .vfs import ArchiveVFS, ChunkMissing, DEFAULT_DIR_MODE

logger = create_logger(__name__)


class Resource(NamedTuple):
    """What this server needs to know about one file system object it serves.

    The tree itself lives in the (shared) archive VFS - this is just the flat view
    of one node of it that building a listing, a PROPFIND response or a download
    needs, so we do not look up the same item metadata over and over.
    """

    is_dir: bool
    mode: int
    mtime: int  # ns
    size: int
    target: str | None  # symlink target


def strip_crlf(value):
    """Remove CR and LF from an HTTP header value, so it can never split the response.

    The values we build are already newline-free (percent-encoded or non-printables
    replaced), so this is defense in depth - and the explicit, recognizable form of the
    CR/LF safety that we (and static analysers) rely on at the header sinks.
    """
    return value.replace("\r", "").replace("\n", "")


def encode_path(path):
    """Percent-encode a borg item path (str with surrogateescape) for use in a URL."""
    return quote(path.encode("utf-8", "surrogateescape"))


def decode_path(path):
    """Decode a percent-encoded URL path to a borg item path (str with surrogateescape)."""
    return unquote_to_bytes(path).decode("utf-8", "surrogateescape")


def http_date(mtime_ns):
    return formatdate(mtime_ns / 1e9, usegmt=True)


def display_time(mtime_ns):
    dt = datetime.fromtimestamp(mtime_ns / 1e9, tz=timezone.utc).astimezone()
    return dt.isoformat(sep=" ", timespec="seconds")


def display_size(size):
    """Format a precise byte count with dots as thousands separators, e.g. '123.456.789'."""
    return f"{size:,}".replace(",", ".")


def guess_content_type(name):
    return mimetypes.guess_type(remove_surrogates(name), strict=False)[0] or "application/octet-stream"


def make_etag(res):
    # archive contents are immutable, so mtime+size identify the content well enough.
    return f'"{res.mtime:x}-{res.size:x}"'


def parse_byte_range(header, size):
    """Parse a Range header value against a resource of *size* bytes.

    Returns (start, end) (both inclusive), None if the header shall be ignored
    (serve the full body then), or "unsatisfiable" (respond with 416 then).
    """
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", header.strip())
    if not m:  # multiple ranges / other units: ignoring the header is allowed
        return None
    start_s, end_s = m.groups()
    if not start_s and not end_s:
        return None
    if not start_s:  # suffix form: the last N bytes
        n = int(end_s)
        if n == 0 or size == 0:
            return "unsatisfiable"
        return max(size - n, 0), size - 1
    start = int(start_s)
    if start >= size:
        return "unsatisfiable"
    end = min(int(end_s), size - 1) if end_s else size - 1
    if end < start:
        return None
    return start, end


# WebDAV support (class 1, read-only), see RFC 4918.

ET.register_namespace("D", "DAV:")

ALLOWED_METHODS = "OPTIONS, GET, HEAD, PROPFIND"

# all live properties this server can provide
DAV_PROPS = (
    "{DAV:}resourcetype",
    "{DAV:}displayname",
    "{DAV:}getcontentlength",
    "{DAV:}getcontenttype",
    "{DAV:}getlastmodified",
    "{DAV:}creationdate",
    "{DAV:}getetag",
    "{DAV:}supportedlock",
    "{DAV:}lockdiscovery",
)


def iso8601(mtime_ns):
    return datetime.fromtimestamp(mtime_ns / 1e9, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_propfind(body):
    """Parse a PROPFIND request body.

    Returns a (mode, props) tuple: ("allprop", None), ("propname", None) or
    ("prop", [tag, ...]), where each tag is a "{namespace}localname" string (the
    same notation ElementTree uses). Raises ValueError for bodies we do not
    understand.

    We parse with expat directly (not with a higher-level XML library) so we can
    reject any DTD via expat's StartDoctypeDeclHandler: a DTD is the only way to
    declare custom internal entities, so rejecting it - before any entity can be
    declared or expanded - makes entity expansion ("billion laughs" / "XML bomb")
    impossible. Doing it in the doctype callback rather than by scanning the raw
    bytes for "<!DOCTYPE" is encoding-proof (a DTD in e.g. UTF-16 does not contain
    those ASCII bytes). We never expand or resolve entities, and _read_body()
    additionally limits the request body to 1 MiB.
    """
    if isinstance(body, str):
        body = body.encode("utf-8")
    if not body.strip():
        return "allprop", None  # RFC 4918: an empty body means allprop

    # expat reports namespaced element names as "uri<sep>local"; using "}" as the
    # separator and prefixing "{" yields the "{uri}local" notation used elsewhere.
    parser = expat.ParserCreate(namespace_separator="}")
    stack = []  # open elements, as "{uri}local"
    saw_propname = [False]
    saw_prop = [False]
    prop_depth = [None]  # nesting depth of the <prop> element, once seen
    props = []  # direct children of <prop> (the requested property names)

    def forbid_dtd(name, sysid, pubid, has_internal_subset):
        raise ValueError("DTD in request body rejected")

    def start_element(name, attrs):
        tag = "{" + name if "}" in name else name
        stack.append(tag)
        if len(stack) == 1 and tag != "{DAV:}propfind":
            raise ValueError("root element is not DAV: propfind")
        if len(stack) == 2 and tag == "{DAV:}propname":
            saw_propname[0] = True
        elif len(stack) == 2 and tag == "{DAV:}prop":
            saw_prop[0] = True
            prop_depth[0] = len(stack)
        elif prop_depth[0] is not None and len(stack) == prop_depth[0] + 1:
            props.append(tag)  # a requested property name

    parser.StartDoctypeDeclHandler = forbid_dtd
    parser.StartElementHandler = start_element
    parser.EndElementHandler = lambda name: stack.pop()
    try:
        parser.Parse(body, True)
    except expat.ExpatError as e:
        raise ValueError(f"malformed PROPFIND body: {e}")

    if saw_propname[0]:
        return "propname", None
    if saw_prop[0]:
        return "prop", props
    return "allprop", None  # allprop, maybe with an include element


def make_prop_element(tag, name, res):
    """Build the XML element for live property *tag* of resource *res*.

    Returns None if the property is not defined for this resource.
    """
    elem = ET.Element(tag)
    if tag == "{DAV:}resourcetype":
        if res.is_dir:
            ET.SubElement(elem, "{DAV:}collection")
    elif tag == "{DAV:}displayname":
        elem.text = remove_surrogates(name)
    elif tag == "{DAV:}getlastmodified":
        elem.text = http_date(res.mtime)
    elif tag == "{DAV:}creationdate":
        elem.text = iso8601(res.mtime)
    elif tag == "{DAV:}getcontentlength":
        if res.is_dir:
            return None
        elem.text = str(res.size)
    elif tag == "{DAV:}getcontenttype":
        if res.is_dir:
            return None
        elem.text = guess_content_type(name)
    elif tag == "{DAV:}getetag":
        if res.is_dir:
            return None
        elem.text = make_etag(res)
    elif tag in ("{DAV:}supportedlock", "{DAV:}lockdiscovery"):
        pass  # empty elements: locking is not supported
    else:
        return None
    return elem


def render_multistatus(resources, mode, requested):
    """Render a PROPFIND result as a multistatus XML document (bytes).

    *resources* is a list of (href, displayname, Resource) tuples, *mode* / *requested*
    are the parse_propfind() results.
    """
    multistatus = ET.Element("{DAV:}multistatus")
    for href, name, res in resources:
        response = ET.SubElement(multistatus, "{DAV:}response")
        ET.SubElement(response, "{DAV:}href").text = href
        found = ET.Element("{DAV:}prop")
        missing = ET.Element("{DAV:}prop")
        if mode == "propname":
            for tag in DAV_PROPS:
                if make_prop_element(tag, name, res) is not None:
                    ET.SubElement(found, tag)
        else:
            for tag in DAV_PROPS if mode == "allprop" else requested:
                elem = make_prop_element(tag, name, res)
                if elem is not None:
                    found.append(elem)
                else:
                    missing.append(ET.Element(tag))
        for prop, status in ((found, "200 OK"), (missing, "404 Not Found")):
            if len(prop) or status == "200 OK":  # always emit the 200 propstat, even if empty
                propstat = ET.SubElement(response, "{DAV:}propstat")
                propstat.append(prop)
                ET.SubElement(propstat, "{DAV:}status").text = f"HTTP/1.1 {status}"
    return b'<?xml version="1.0" encoding="utf-8" ?>\n' + ET.tostring(multistatus)


# the official borg logo (docs/_static/logo.svg, "borg" in vectorized Black Ops One),
# without the background rect and with the fill color controlled via CSS currentColor.
LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 133.333" role="img" aria-label="Borg">'
    '<path transform="translate(20.9086, 32.2192)" fill="currentColor" d="M43.75 13.8021L26.6667 13.8021L26.6667 0'
    "L53.3854 0L67.2396 13.8021L67.2396 27.8646L60.3125 34.7917L67.2396 41.7187L67.2396 55.3125L53.3854 69.1146"
    "L26.6667 69.1146L26.6667 55.3125L43.75 55.3125L43.75 40.5729L26.6667 40.5729L26.6667 28.5417L43.75 28.5417ZM0 0"
    'L23.0208 0L23.0208 69.1146L0 69.1146Z"/>'
    '<path transform="translate(97.6794, 46.0213)" fill="currentColor" d="M62.1354 41.5104L48.3333 55.3125'
    "L32.9167 55.3125L32.9167 42.3958L38.6458 42.3958L38.6458 13.8021L32.9167 13.8021L32.9167 0L48.3333 0"
    "L62.1354 13.8021ZM23.2813 42.3958L29.2708 42.3958L29.2708 55.3125L13.8021 55.3125L0 41.5104L0 13.8021"
    'L13.8021 0L29.2708 0L29.2708 13.8021L23.2813 13.8021Z"/>'
    '<path transform="translate(170.231, 46.0213)" fill="currentColor" d="M36.5104 13.8021L26.7187 13.8021'
    "L26.7187 7.76042L34.4271 0L48.3854 0L59.5833 12.9167L59.5833 27.2396L36.5104 27.2396ZM0 55.3125L0 0"
    'L23.0208 0L23.0208 55.3125Z"/>'
    '<path transform="translate(236.429, 46.0213)" fill="currentColor" d="M36.875 13.8021L26.6667 13.8021L26.6667 0'
    "L46.0937 0L59.8958 13.8021L59.8958 60.7812L46.0937 74.6875L15.7292 74.6875L8.80208 67.7083L8.80208 62.6042"
    "L36.875 62.6042ZM33.2292 42.3958L33.2292 48.4896L26.3542 55.3125L13.8021 55.3125L0 41.5104L0 13.8021L13.8021 0"
    'L23.0208 0L23.0208 42.3958Z"/>'
    "</svg>"
)

# "download to tray" icon (inline SVG, color via currentColor), shown next to a
# directory heading to download that directory as a tar archive.
DOWNLOAD_ICON_SVG = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
    'stroke-linecap="round" stroke-linejoin="round" role="img" aria-label="download as tar">'
    '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
    '<polyline points="7 10 12 15 17 10"/>'
    '<line x1="12" y1="15" x2="12" y2="3"/>'
    "</svg>"
)

PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
/* green-on-black terminal style, similar to www.borgbackup.org */
:root {{ color-scheme: dark; }}
body {{
  background: #020503;
  color: #d7e8da;
  font-family: ui-monospace, Menlo, Monaco, "Cascadia Mono", "Segoe UI Mono",
               "Roboto Mono", "Ubuntu Monospace", "Source Code Pro", monospace;
  margin: 2em;
}}
h1 {{ color: #22d045; font-size: 1.4em; }}
h1 a {{ color: inherit; }}
h1 a.dl {{ margin-left: 0.5em; opacity: 0.75; }}
h1 a.dl:hover {{ opacity: 1; text-decoration: none; }}
h1 a.dl svg {{ width: 0.85em; height: 0.85em; vertical-align: -0.06em; }}
a {{ color: #22d045; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
table {{ border-collapse: collapse; }}
th, td {{ text-align: left; padding: 0.25em 1.5em 0.25em 0; }}
th {{ color: #8aa892; font-weight: normal; border-bottom: 1px solid rgba(34, 208, 69, 0.22); }}
th.size, td.size {{ text-align: right; }}
td.dim {{ color: #8aa892; }}
tr:hover td {{ background: rgba(34, 208, 69, 0.07); }}
.head {{ display: flex; justify-content: space-between; align-items: center; gap: 1em; }}
.head a.logo {{ color: #22d045; flex: none; }}
.head a.logo svg {{ width: 96px; height: 40px; display: block; }}
</style>
</head>
<body>
<div class="head">
<h1>{heading}</h1>
<a class="logo" href="/">{logo}</a>
</div>
<table>
<tr><th>Name</th><th class="size">Size</th><th>Modified</th></tr>
{rows}
</table>
</body>
</html>
"""


def render_page(title, rows, heading=None):
    """Render a listing page; *title* is plain text, *heading* optional h1 HTML (default: the title)."""
    heading = heading if heading is not None else html.escape(title)
    page = PAGE_TEMPLATE.format(title=html.escape(title), heading=heading, rows="\n".join(rows), logo=LOGO_SVG)
    return page.encode("utf-8")


def make_breadcrumbs(segments):
    """Build h1 HTML for a path: each parent segment links to its directory (for quick
    navigation); the last segment is the current directory and is shown as plain text."""
    parts = []
    href = "/"
    last = len(segments) - 1
    for i, segment in enumerate(segments):
        href += encode_path(segment) + "/"
        text = html.escape(remove_surrogates(segment))
        parts.append(text if i == last else f'<a href="{href}">{text}</a>')
    return "/".join(parts) + "/"


def make_row(href, text, size="", mtime_ns=None):
    modified = display_time(mtime_ns) if mtime_ns is not None else ""
    if href is not None:
        name_cell = f'<a href="{href}">{html.escape(text)}</a>'
    else:
        name_cell = html.escape(text)
    return f'<tr><td>{name_cell}</td><td class="size dim">{size}</td><td class="dim">{modified}</td></tr>'


class WebDAVHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 keeps connections alive by default, so a client can reuse one connection
    # for its many requests instead of reconnecting each time.
    protocol_version = "HTTP/1.1"
    # Disable Nagle's algorithm (set TCP_NODELAY): its interaction with delayed ACKs can
    # add ~40 ms to a small request/response, which really hurts WebDAV clients that issue
    # lots of small PROPFIND/HEAD/GET requests.
    disable_nagle_algorithm = True
    # Buffer the response so the several small writes of one response (status line, headers,
    # HTML rows, tar block framing) coalesce into few packets/syscalls; writes larger than
    # the buffer (file/tar chunk data) still pass straight through. handle_one_request()
    # flushes wfile after each request, so buffering does not delay the response.
    wbufsize = 64 * 1024
    server_version = f"borg-webdav/{__version__}"
    sys_version = ""  # do not tell clients about the python version we use

    # set on the handler class by make_server():
    vfs = None  # the shared archive VFS, see vfs.py

    def version_string(self):
        # the base class would append sys_version, giving a trailing space if it is empty.
        return self.server_version

    def log_message(self, format, *args):
        logger.debug("webdav: %s - %s", self.address_string(), format % args)

    def do_GET(self):
        self._guarded(self._handle_get_head, False)

    def do_HEAD(self):
        self._guarded(self._handle_get_head, True)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", ALLOWED_METHODS)
        self.send_header("DAV", "1")
        self.send_header("MS-Author-Via", "DAV")  # helps (older) Windows WebDAV clients
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PROPFIND(self):
        self._guarded(self._handle_propfind)

    def _method_not_allowed(self):
        # this is a read-only server, reject everything that would modify or lock something.
        self.send_response(405)
        self.send_header("Allow", ALLOWED_METHODS)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.close_connection = True  # we did not read a request body the client may have sent

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_PROPPATCH = _method_not_allowed
    do_MKCOL = _method_not_allowed
    do_COPY = _method_not_allowed
    do_MOVE = _method_not_allowed
    do_LOCK = _method_not_allowed
    do_UNLOCK = _method_not_allowed

    def _guarded(self, method, *args):
        try:
            method(*args)
        except BrokenPipeError:
            self.close_connection = True
        except Exception:
            logger.exception("webdav: unhandled error while serving %s", self.requestline)
            try:
                self.send_error(500)
            except OSError:
                self.close_connection = True

    def _parse_segments(self):
        """Parse self.path into decoded path segments; returns None for invalid paths."""
        path, _, _query = self.path.partition("?")
        path = decode_path(path)
        segments = [s for s in path.split("/") if s]
        if any(s in (".", "..") for s in segments):
            return None
        return segments, path.endswith("/")

    def _wants_tar(self):
        """True if the request asks for a tar download of a directory (``?tar`` or ``?tar=1``)."""
        query = self.path.partition("?")[2]
        return "tar" in parse_qs(query, keep_blank_values=True)

    def _read_body(self):
        """Read a request body; returns None (after sending an error) if that is not possible."""
        if self.headers.get("Transfer-Encoding"):
            self.send_error(501, explain="request bodies with Transfer-Encoding are not supported")
            self.close_connection = True
            return None
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.send_error(400)
            self.close_connection = True
            return None
        if length < 0 or length > 1024 * 1024:
            self.send_error(413)
            self.close_connection = True
            return None
        return self.rfile.read(length)

    def _handle_get_head(self, head):
        parsed = self._parse_segments()
        if parsed is None:
            self.send_error(404)
            return
        segments, dir_syntax = parsed
        if not segments:
            self._send_archive_list(head)
            return
        try:
            # use the canonical (as stored in the archive) segments from here on, so that a
            # request in a different Unicode normalization still names the stored items.
            segments, node = self.vfs.resolve(segments)
        except KeyError:
            self.send_error(404)
            return
        res = self._resource(node)
        if res.is_dir:
            if not dir_syntax:
                self._redirect_to_dir(segments)
                return
            if self._wants_tar():
                self._send_tar(segments, head)
                return
            self._send_dir_listing(segments, node, head)
        elif stat.S_ISREG(res.mode):
            self._send_file(segments[-1], node, res, head)
        elif stat.S_ISLNK(res.mode):
            self.send_error(
                403, explain=f"symbolic link (target: {remove_surrogates(res.target or '?')}), not downloadable"
            )
        else:
            self.send_error(403, explain="special file, not downloadable")

    def _resource(self, node):
        """Return the Resource describing *node*."""
        item = self.vfs.get_item(node.ino)
        return Resource(
            is_dir=node.is_dir, mode=item.mode, mtime=item.mtime, size=item.get_size(), target=item.get("target")
        )

    def _handle_propfind(self):
        body = self._read_body()
        if body is None:
            return
        parsed = self._parse_segments()
        if parsed is None:
            self.send_error(404)
            return
        depth = self.headers.get("Depth", "infinity").strip().lower()
        if depth not in ("0", "1"):
            # RFC 4918 allows servers to reject PROPFIND requests with unlimited depth.
            self.send_error(403, explain="PROPFIND with Depth: infinity is not supported")
            return
        try:
            mode, requested = parse_propfind(body)
        except ValueError:
            self.send_error(400, explain="invalid PROPFIND request body")
            return
        try:
            resources = self._propfind_resources(parsed[0], depth)
        except KeyError:
            self.send_error(404)
            return
        result = render_multistatus(resources, mode, requested)
        self.send_response(207, "Multi-Status")
        self.send_header("Content-Type", 'application/xml; charset="utf-8"')
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    def _propfind_resources(self, segments, depth):
        """Return the [(href, displayname, Resource), ...] a PROPFIND on *segments* refers to."""
        resources = []
        if not segments:  # server root: the list of archives
            resources.append(("/", "/", Resource(True, DEFAULT_DIR_MODE, self.vfs.root_mtime, 0, None)))
            if depth == "1":
                for name in sorted(self.vfs.archives):
                    archive_info = self.vfs.archives[name]
                    mtime_ns = int(archive_info.ts.timestamp() * 1e9)
                    res = Resource(True, DEFAULT_DIR_MODE, mtime_ns, 0, None)
                    resources.append(("/" + encode_path(name) + "/", name, res))
            return resources
        segments, node = self.vfs.resolve(segments)  # may raise KeyError
        res = self._resource(node)
        if not (res.is_dir or stat.S_ISREG(res.mode)):
            raise KeyError(segments[-1])  # symlinks and special files are not exposed via WebDAV
        base = "/" + "/".join(encode_path(s) for s in segments)
        if not res.is_dir:
            return [(base, segments[-1], res)]
        resources.append((base + "/", segments[-1], res))
        if depth == "1":
            for name, child in sorted(self.vfs.children(node), key=lambda kv: kv[0]):
                child_res = self._resource(child)
                if child_res.is_dir:
                    resources.append((f"{base}/{encode_path(name)}/", name, child_res))
                elif stat.S_ISREG(child_res.mode):
                    resources.append((f"{base}/{encode_path(name)}", name, child_res))
                # symlinks and special files are not exposed via WebDAV
        return resources

    def _redirect_to_dir(self, segments):
        # Build the redirect target by percent-encoding the parsed path segments:
        # quote() only outputs URL-safe ASCII for the path. Preserve the query string
        # (e.g. "?tar=1") so redirecting a directory URL that lacks the trailing slash
        # does not drop it. The query is already percent-encoded by the client; the
        # strip_crlf() below removes any CR/LF, so the Location cannot split the response.
        location = "/" + "/".join(encode_path(s) for s in segments) + "/"
        query = self.path.partition("?")[2]
        if query:
            location += "?" + query
        location = strip_crlf(location)
        self.send_response(301)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_page(self, page, head):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if not head:
            self.wfile.write(page)

    def _send_archive_list(self, head):
        rows = []
        for name in sorted(self.vfs.archives):
            archive_info = self.vfs.archives[name]
            mtime_ns = int(archive_info.ts.timestamp() * 1e9)
            rows.append(make_row(encode_path(name) + "/", name + "/", mtime_ns=mtime_ns))
        self._send_page(render_page("Archives", rows), head)

    def _send_dir_listing(self, segments, node, head):
        title = "/".join(remove_surrogates(s) for s in segments) + "/"
        # heading = breadcrumb path + an icon to download this directory as a tar archive
        heading = make_breadcrumbs(segments) + (
            '<a class="dl" href="?tar=1" title="Download this directory as a .tar archive'
            f' (preserves metadata)">{DOWNLOAD_ICON_SVG}</a>'
        )
        rows = [make_row("../", "..")]
        children = [(name, self._resource(child)) for name, child in self.vfs.children(node)]
        children.sort(key=lambda kv: (not kv[1].is_dir, kv[0]))  # directories first
        for name, child in children:
            display_name = remove_surrogates(name)
            if child.is_dir:
                rows.append(make_row(encode_path(name) + "/", display_name + "/", mtime_ns=child.mtime))
            elif stat.S_ISREG(child.mode):
                rows.append(
                    make_row(encode_path(name), display_name, size=display_size(child.size), mtime_ns=child.mtime)
                )
            elif stat.S_ISLNK(child.mode):
                text = f"{display_name} -> {remove_surrogates(child.target or '?')}"
                rows.append(make_row(None, text, mtime_ns=child.mtime))
            else:
                rows.append(make_row(None, display_name, mtime_ns=child.mtime))
        self._send_page(render_page(title, rows, heading=heading), head)

    def _send_file(self, name, node, res, head):
        etag = make_etag(res)
        if_none_match = self.headers.get("If-None-Match")
        if if_none_match:
            client_tags = [t.strip() for t in if_none_match.split(",")]
            if "*" in client_tags or etag in client_tags:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.end_headers()
                return
        byte_range = None
        range_header = self.headers.get("Range")
        if range_header:
            if_range = self.headers.get("If-Range")
            if if_range is None or if_range.strip() == etag:
                byte_range = parse_byte_range(range_header, res.size)
        if byte_range == "unsatisfiable":
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{res.size}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if byte_range:
            start, end = byte_range
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{res.size}")
        else:
            start, end = 0, res.size - 1
            self.send_response(200)
        self.send_header("Content-Type", guess_content_type(name))
        self.send_header("Content-Length", str(end - start + 1 if res.size else 0))
        self.send_header("Last-Modified", http_date(res.mtime))
        self.send_header("ETag", etag)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("X-Content-Type-Options", "nosniff")
        content_disposition = self._content_disposition(name)  # CR/LF-sanitized, see there
        self.send_header("Content-Disposition", content_disposition)
        self.end_headers()
        if head or res.size == 0:
            return  # no body to send (and Content-Length is 0 for an empty file)
        chunks = self.vfs.get_item(node.ino).get("chunks")
        if not chunks:
            # anomaly: a non-empty file with no chunks list (e.g. corrupted metadata). We
            # already sent Content-Length > 0, so abort the connection instead of leaving
            # the client waiting forever for body bytes that will never arrive.
            logger.error(
                "webdav: file %s has size %d but no chunks, aborting the connection.", remove_surrogates(name), res.size
            )
            self.close_connection = True
            return
        # the reader fetches only the chunks overlapping the requested range (the chunk
        # sizes are known in advance), each one under the repository lock - but we write
        # to the client outside of it, so one slow client cannot block other requests.
        # pos_key: a mounted file system reads a big file with many sequential range
        # requests - remember where in the chunk list they got us.
        try:
            for data in self.vfs.reader.iter_data(chunks, start, end - start + 1, pos_key=node.ino):
                self.wfile.write(data)
        except ChunkMissing:
            # chunk missing in repository - never serve silently corrupted data:
            # abort the connection, the client sees a short read (Content-Length mismatch).
            logger.error("webdav: chunk missing while serving %s, aborting the connection.", remove_surrogates(name))
            self.close_connection = True

    def _send_chunked(self, data):
        """Write one HTTP/1.1 chunked-transfer-encoding block; *data* must be non-empty."""
        self.wfile.write(b"%x\r\n" % len(data))
        self.wfile.write(data)
        self.wfile.write(b"\r\n")

    def _tar_warning(self, fmt, *args):
        logger.warning("webdav: " + fmt, *args)

    def _send_tar(self, segments, head):
        """Stream the directory subtree at *segments* as a PAX tar archive.

        Unlike a plain file download, a tar preserves POSIX metadata (owner, group,
        mode, sub-second timestamps, symlinks, special files, xattrs, ACLs), so it is
        the metadata-lossless way to restore a whole directory over HTTP. The reused
        item -> TarInfo conversion (borg export-tar) needs the full item metadata, so
        we re-iterate the archive items here rather than using the lightweight VFS tree.

        The tar size is not known in advance (PAX header sizes vary), so we stream it
        with chunked transfer encoding. Repository access (item iteration and chunk
        fetching) is serialized under the VFS lock, but each chunk is written to the
        client outside the lock - so a slow client cannot block other requests, and the
        LockRefresher can keep the repository lock alive during a long download.
        """
        # lazy import: pulling in the archiver package at module import time would be
        # heavy (all subcommands) and risks an import cycle; by the time we serve a
        # request the package is fully imported anyway.
        from .archiver.tar_cmds import item_to_tarinfo, item_to_paxheaders

        archive_name = segments[0]
        prefix = "/".join(segments[1:])  # borg path of the requested dir ("" = whole archive)
        # root the tar at the requested directory: strip everything above it from the paths.
        parent = prefix.rsplit("/", 1)[0] if "/" in prefix else ""
        strip = len(parent) + 1 if parent else 0

        def want(item):
            if not prefix:
                return True
            return item.path == prefix or item.path.startswith(prefix + "/")

        # download_name is derived from the client-supplied URL path, so sanitize it
        # against header injection (CR/LF) just like a normal download, see there.
        content_disposition = self._content_disposition(segments[-1] + ".tar")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-tar")
        self.send_header("Content-Disposition", content_disposition)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if head:
            return

        with self.vfs.lock:
            archive = Archive(self.vfs.manifest, self.vfs.archives[archive_name].id)
            item_iter = archive.iter_items(want)

        hlm = HardLinkManager(id_type=bytes, info_type=str)  # hlid -> (stripped) path of the first link
        complete = False
        try:
            while True:
                with self.vfs.lock:
                    try:
                        item = next(item_iter)
                    except StopIteration:
                        break
                if strip:
                    item.path = item.path[strip:]
                tarinfo, needs_content = item_to_tarinfo(item, hlm, warning=self._tar_warning)
                if tarinfo is None:
                    continue  # unsupported item type, skipped (with a warning)
                tarinfo.pax_headers = item_to_paxheaders("PAX", item)
                self._send_chunked(tarinfo.tobuf(tarfile.PAX_FORMAT, tarfile.ENCODING, "surrogateescape"))
                if needs_content and not self._send_tar_content(item, tarinfo.size):
                    return  # a chunk was missing: leave the chunked stream unterminated (see finally)
            # end-of-archive marker (two zero blocks), then terminate the chunked stream.
            self._send_chunked(b"\0" * (tarfile.BLOCKSIZE * 2))
            self.wfile.write(b"0\r\n\r\n")
            complete = True
        finally:
            if not complete:
                # do not send the terminating 0-length chunk, so the client can tell the
                # tar is truncated (never present a corrupt archive as if it were complete).
                self.close_connection = True

    def _send_tar_content(self, item, size):
        """Stream *item*'s file content into the tar, padded to a 512-byte block boundary.

        Returns False (after logging) if the content cannot be produced in full (a chunk
        missing in the repository, or a non-empty item with no chunks list), so the caller
        aborts the connection instead of emitting a silently corrupted (short) tar member.
        """
        chunks = item.get("chunks") or []
        if size > 0 and not chunks:
            # anomaly: a non-empty item with no chunks list (e.g. corrupted metadata). The
            # tar header already declared size > 0, so we cannot emit a valid member.
            logger.error(
                "webdav: tar member %s has size %d but no chunks, aborting the connection.",
                remove_surrogates(item.path),
                size,
            )
            return False
        try:
            # fetches under the lock, writes to the client outside it (see _send_tar).
            for data in self.vfs.reader.iter_data(chunks, 0, size):
                self._send_chunked(data)
        except ChunkMissing:
            logger.error(
                "webdav: chunk missing while streaming tar member %s, aborting the connection.",
                remove_surrogates(item.path),
            )
            return False
        padding = (tarfile.BLOCKSIZE - size % tarfile.BLOCKSIZE) % tarfile.BLOCKSIZE
        if padding:
            self._send_chunked(b"\0" * padding)
        return True

    @staticmethod
    def _content_disposition(name):
        # File names from an archive can contain any byte except NUL and "/", including
        # CR/LF - a file name like 'x\r\nEvil-Header: ...' must not enable the client
        # to be attacked via HTTP header injection ("response splitting"):
        # - the fallback name replaces everything non-printable (this kills CR/LF) and
        #   non-ascii, and the quotes that could end the quoted-string.
        # - the RFC 8187 encoded name percent-encodes everything critical (quote()
        #   only outputs URL-safe ASCII).
        fallback = "".join(c if c.isprintable() else "_" for c in remove_surrogates(name))
        fallback = fallback.encode("ascii", "replace").decode("ascii").replace('"', "'")
        encoded = quote(name.encode("utf-8", "surrogateescape"))
        result = f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"
        return strip_crlf(result)  # no-op by construction, but makes the CR/LF safety explicit


def make_server(manifest, args, bind="127.0.0.1", port=8000):
    """Create a ThreadingHTTPServer serving the archives selected by *args*.

    The server object gets a repo_lock attribute; all repository access of the
    server threads is serialized with it (use it for e.g. LockRefresher, too).
    """
    repo_lock = threading.RLock()
    vfs = ArchiveVFS(manifest, args, lock=repo_lock)
    vfs.create_filesystem()

    handler_class = type("WebDAVHandler", (WebDAVHandler,), dict(vfs=vfs))
    server = ThreadingHTTPServer((bind, port), handler_class)
    server.daemon_threads = True
    server.repo_lock = repo_lock
    return server
