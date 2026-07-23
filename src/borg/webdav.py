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
import threading
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote_to_bytes
from xml.etree import ElementTree as ET
from xml.parsers import expat

from . import __version__
from .archive import Archive
from .constants import *  # NOQA
from .helpers import bin_to_hex, remove_surrogates
from .logger import create_logger

logger = create_logger(__name__)

DEFAULT_DIR_MODE = 0o40755


class Node:
    """A node in an archive's directory tree: a directory (children is a dict) or a leaf."""

    __slots__ = ("mode", "mtime", "size", "chunks", "target", "children")

    def __init__(self, mode, mtime=0, size=0, chunks=None, target=None, children=None):
        self.mode = mode
        self.mtime = mtime  # ns
        self.size = size
        self.chunks = chunks
        self.target = target  # symlink target
        self.children = children  # {name(str): Node} for directories, None otherwise

    @property
    def is_dir(self):
        return self.children is not None


class ArchiveVFS:
    """Read-only view of the archives selected by the archive filter args.

    The top level maps (deduplicated) archive names to lazily built directory trees.
    All repository access happens under repo_lock, because borgstore connections are
    not thread-safe.
    """

    def __init__(self, manifest, args, repo_lock):
        self.manifest = manifest
        self.repo_lock = repo_lock
        archives = manifest.archives.list_considering(args)
        # deduplicate archive names (archives of a series all share the same name)
        name_counter = {}
        for archive in archives:
            name_counter[archive.name] = name_counter.get(archive.name, 0) + 1
        self.archives = {}  # display name -> ArchiveInfo
        for archive in archives:
            name = archive.name
            if name_counter[name] > 1:
                name += f"-{bin_to_hex(archive.id):.8}"
            self.archives[name] = archive
        self._trees = {}  # display name -> (root Node, DownloadPipeline)
        timestamps = [archive.ts for archive in archives]
        self.root_mtime = int(max(timestamps).timestamp() * 1e9) if timestamps else 0

    def get_root(self, name):
        """Return (root Node, pipeline) for archive *name*, building the tree on first access."""
        try:
            return self._trees[name]
        except KeyError:
            pass
        archive_info = self.archives[name]  # may raise KeyError -> 404
        with self.repo_lock:
            if name not in self._trees:  # re-check under lock
                self._trees[name] = self._build_tree(archive_info)
        return self._trees[name]

    def _build_tree(self, archive_info):
        logger.debug("webdav: building tree for archive %s ...", remove_surrogates(archive_info.name))
        archive = Archive(self.manifest, archive_info.id)
        archive_mtime = int(archive_info.ts.timestamp() * 1e9)
        root = Node(DEFAULT_DIR_MODE, mtime=archive_mtime, children={})
        for item in archive.iter_items():
            segments = [s for s in item.path.split("/") if s]
            if not segments:
                continue
            node = root
            for segment in segments[:-1]:
                child = node.children.get(segment)
                if child is None or not child.is_dir:
                    # intermediate directory not (yet) seen as an item: synthesize it
                    child = Node(DEFAULT_DIR_MODE, mtime=archive_mtime, children={})
                    node.children[segment] = child
                node = child
            name = segments[-1]
            if stat.S_ISDIR(item.mode):
                existing = node.children.get(name)
                if existing is not None and existing.is_dir:
                    # was synthesized before the dir item was seen: update metadata in place
                    existing.mode = item.mode
                    existing.mtime = item.mtime
                else:
                    node.children[name] = Node(item.mode, mtime=item.mtime, children={})
            else:
                node.children[name] = Node(
                    item.mode,
                    mtime=item.mtime,
                    size=item.get_size(),
                    chunks=item.get("chunks"),
                    target=item.get("target"),
                )
        return root, archive.pipeline

    def resolve(self, segments):
        """Resolve path segments (first one is the archive name) to (Node, pipeline).

        Raises KeyError if not found.
        """
        root, pipeline = self.get_root(segments[0])
        node = root
        for segment in segments[1:]:
            if not node.is_dir:
                raise KeyError(segment)
            node = node.children[segment]
        return node, pipeline


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


def make_etag(node):
    # archive contents are immutable, so mtime+size identify the content well enough.
    return f'"{node.mtime:x}-{node.size:x}"'


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


def reject_dtd(body):
    """Raise ValueError if *body* contains an XML DTD (<!DOCTYPE ...>).

    A DTD is the only way to declare custom internal entities, so rejecting it
    rules out entity expansion attacks ("billion laughs"). We use expat's own
    doctype callback rather than a substring check on the raw bytes, so this is
    independent of the document encoding (a DTD in e.g. UTF-16 does not contain
    the ASCII bytes "<!DOCTYPE"). The callback fires at the start of the doctype
    declaration, before any entity is declared or expanded.
    """
    parser = expat.ParserCreate()

    def forbid_dtd(name, sysid, pubid, has_internal_subset):
        raise ValueError("DTD in request body rejected")

    parser.StartDoctypeDeclHandler = forbid_dtd
    try:
        parser.Parse(body if isinstance(body, bytes) else body.encode("utf-8"), True)
    except expat.ExpatError:
        pass  # malformed XML: the real parse below raises the canonical ParseError


def parse_propfind(body):
    """Parse a PROPFIND request body.

    Returns a (mode, props) tuple: ("allprop", None), ("propname", None) or
    ("prop", [tag, ...]). Raises ValueError or ET.ParseError for bodies we do
    not understand.
    """
    if not body.strip():
        return "allprop", None  # RFC 4918: an empty body means allprop
    reject_dtd(body)
    # DTDs are rejected above, so no internal entities can be declared and no
    # entity expansion ("billion laughs" / "XML bomb") is possible - additionally,
    # the request body is limited to 1 MiB by _read_body().
    root = ET.fromstring(body)  # codeql[py/xml-bomb]: DTDs (thus custom entities) rejected by reject_dtd()
    if root.tag != "{DAV:}propfind":
        raise ValueError("root element is not DAV: propfind")
    if root.find("{DAV:}propname") is not None:
        return "propname", None
    prop = root.find("{DAV:}prop")
    if prop is not None:
        return "prop", [child.tag for child in prop]
    return "allprop", None  # allprop, maybe with an include element


def make_prop_element(tag, name, node):
    """Build the XML element for live property *tag* of resource *node*.

    Returns None if the property is not defined for this resource.
    """
    elem = ET.Element(tag)
    if tag == "{DAV:}resourcetype":
        if node.is_dir:
            ET.SubElement(elem, "{DAV:}collection")
    elif tag == "{DAV:}displayname":
        elem.text = remove_surrogates(name)
    elif tag == "{DAV:}getlastmodified":
        elem.text = http_date(node.mtime)
    elif tag == "{DAV:}creationdate":
        elem.text = iso8601(node.mtime)
    elif tag == "{DAV:}getcontentlength":
        if node.is_dir:
            return None
        elem.text = str(node.size)
    elif tag == "{DAV:}getcontenttype":
        if node.is_dir:
            return None
        elem.text = guess_content_type(name)
    elif tag == "{DAV:}getetag":
        if node.is_dir:
            return None
        elem.text = make_etag(node)
    elif tag in ("{DAV:}supportedlock", "{DAV:}lockdiscovery"):
        pass  # empty elements: locking is not supported
    else:
        return None
    return elem


def render_multistatus(resources, mode, requested):
    """Render a PROPFIND result as a multistatus XML document (bytes).

    *resources* is a list of (href, displayname, node) tuples, *mode* / *requested*
    are the parse_propfind() results.
    """
    multistatus = ET.Element("{DAV:}multistatus")
    for href, name, node in resources:
        response = ET.SubElement(multistatus, "{DAV:}response")
        ET.SubElement(response, "{DAV:}href").text = href
        found = ET.Element("{DAV:}prop")
        missing = ET.Element("{DAV:}prop")
        if mode == "propname":
            for tag in DAV_PROPS:
                if make_prop_element(tag, name, node) is not None:
                    ET.SubElement(found, tag)
        else:
            for tag in DAV_PROPS if mode == "allprop" else requested:
                elem = make_prop_element(tag, name, node)
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
    """Build h1 HTML for a path: each segment linked to its directory, for quick navigation."""
    parts = []
    href = "/"
    for segment in segments:
        href += encode_path(segment) + "/"
        parts.append(f'<a href="{href}">{html.escape(remove_surrogates(segment))}</a>')
    return "/".join(parts) + "/"


def make_row(href, text, size="", mtime_ns=None):
    modified = display_time(mtime_ns) if mtime_ns is not None else ""
    if href is not None:
        name_cell = f'<a href="{href}">{html.escape(text)}</a>'
    else:
        name_cell = html.escape(text)
    return f'<tr><td>{name_cell}</td><td class="size dim">{size}</td><td class="dim">{modified}</td></tr>'


class WebDAVHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"borg-webdav/{__version__}"
    sys_version = ""  # do not tell clients about the python version we use

    # set on the handler class by make_server():
    vfs = None
    repo_lock = None

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

    do_POST = do_PUT = do_DELETE = do_PATCH = _method_not_allowed
    do_PROPPATCH = do_MKCOL = do_COPY = do_MOVE = do_LOCK = do_UNLOCK = _method_not_allowed

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
            node, pipeline = self.vfs.resolve(segments)
        except KeyError:
            self.send_error(404)
            return
        if node.is_dir:
            if not dir_syntax:
                self._redirect_to_dir(segments)
                return
            self._send_dir_listing(segments, node, head)
        elif stat.S_ISREG(node.mode):
            self._send_file(segments[-1], node, pipeline, head)
        elif stat.S_ISLNK(node.mode):
            self.send_error(
                403, explain=f"symbolic link (target: {remove_surrogates(node.target or '?')}), not downloadable"
            )
        else:
            self.send_error(403, explain="special file, not downloadable")

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
        except (ET.ParseError, ValueError):
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
        """Return the [(href, displayname, node), ...] a PROPFIND on *segments* refers to."""
        resources = []
        if not segments:  # server root: the list of archives
            resources.append(("/", "/", Node(DEFAULT_DIR_MODE, mtime=self.vfs.root_mtime, children={})))
            if depth == "1":
                for name in sorted(self.vfs.archives):
                    archive_info = self.vfs.archives[name]
                    node = Node(DEFAULT_DIR_MODE, mtime=int(archive_info.ts.timestamp() * 1e9), children={})
                    resources.append(("/" + encode_path(name) + "/", name, node))
            return resources
        node, _ = self.vfs.resolve(segments)  # may raise KeyError
        if not (node.is_dir or stat.S_ISREG(node.mode)):
            raise KeyError(segments[-1])  # symlinks and special files are not exposed via WebDAV
        base = "/" + "/".join(encode_path(s) for s in segments)
        if not node.is_dir:
            return [(base, segments[-1], node)]
        resources.append((base + "/", segments[-1], node))
        if depth == "1":
            for name, child in sorted(node.children.items()):
                if child.is_dir:
                    resources.append((f"{base}/{encode_path(name)}/", name, child))
                elif stat.S_ISREG(child.mode):
                    resources.append((f"{base}/{encode_path(name)}", name, child))
                # symlinks and special files are not exposed via WebDAV
        return resources

    def _redirect_to_dir(self, segments):
        # Build the redirect target by percent-encoding the parsed path segments:
        # quote() only outputs URL-safe ASCII, so the Location value cannot contain
        # CR/LF or other header-splitting characters, no matter what the client sent.
        location = "/" + "/".join(encode_path(s) for s in segments) + "/"
        self.send_response(301)
        self.send_header("Location", location)  # codeql[py/http-response-splitting]
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
        heading = make_breadcrumbs(segments)
        rows = [make_row("../", "..")]
        children = sorted(node.children.items(), key=lambda kv: (not kv[1].is_dir, kv[0]))
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

    def _send_file(self, name, node, pipeline, head):
        etag = make_etag(node)
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
                byte_range = parse_byte_range(range_header, node.size)
        if byte_range == "unsatisfiable":
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{node.size}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if byte_range:
            start, end = byte_range
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{node.size}")
        else:
            start, end = 0, node.size - 1
            self.send_response(200)
        self.send_header("Content-Type", guess_content_type(name))
        self.send_header("Content-Length", str(end - start + 1 if node.size else 0))
        self.send_header("Last-Modified", http_date(node.mtime))
        self.send_header("ETag", etag)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("X-Content-Type-Options", "nosniff")
        content_disposition = self._content_disposition(name)  # sanitized, see there
        self.send_header("Content-Disposition", content_disposition)  # codeql[py/http-response-splitting]
        self.end_headers()
        if head or not node.chunks or node.size == 0:
            return
        # select only the chunks overlapping the requested range, so nothing else
        # gets fetched and decrypted (the chunk sizes are known in advance).
        selected, first_offset, pos = [], 0, 0
        for entry in node.chunks:
            if pos + entry.size <= start:
                pos += entry.size
                continue
            if pos > end:
                break
            if not selected:
                first_offset = start - pos
            selected.append(entry)
            pos += entry.size
        remaining = end - start + 1
        chunk_iter = pipeline.fetch_many(selected, ro_type=ROBJ_FILE_STREAM, replacement_chunk=False)
        while remaining > 0:
            # serialize repository access, but write to the client outside the lock,
            # so one slow client cannot block other requests for the whole download.
            with self.repo_lock:
                try:
                    data = next(chunk_iter)
                except StopIteration:
                    break
            if data is None:
                # chunk missing in repository - never serve silently corrupted data:
                # abort the connection, the client sees a short read (Content-Length mismatch).
                logger.error(
                    "webdav: chunk missing while serving %s, aborting the connection.", remove_surrogates(name)
                )
                self.close_connection = True
                return
            if first_offset:
                data = data[first_offset:]
                first_offset = 0
            if len(data) > remaining:
                data = data[:remaining]
            self.wfile.write(data)
            remaining -= len(data)

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
        return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"


def make_server(manifest, args, bind="127.0.0.1", port=8000):
    """Create a ThreadingHTTPServer serving the archives selected by *args*.

    The server object gets a repo_lock attribute; all repository access of the
    server threads is serialized with it (use it for e.g. LockRefresher, too).
    """
    repo_lock = threading.RLock()
    vfs = ArchiveVFS(manifest, args, repo_lock)

    handler_class = type("WebDAVHandler", (WebDAVHandler,), dict(vfs=vfs, repo_lock=repo_lock))
    server = ThreadingHTTPServer((bind, port), handler_class)
    server.daemon_threads = True
    server.repo_lock = repo_lock
    return server
