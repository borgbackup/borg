"""Build, publish and read monitoring reports (see crypto/monitoring.py for the crypto).

Each backup-side command (create, prune, ...) appends one report object to the repo's
``monitoring/`` namespace; a monitoring system reads them back and verifies them. The
on-disk object is::

    byte 0: format version
    byte 1: body type (0 = plaintext JSON, 1 = sealed: HPKE(ed25519-sign || JSON))
    rest:   body

The HPKE seal is bound (via aad) to the repository id, which both sides obtain from the
repository they are talking to - it is never trusted from inside the ciphertext.

Objects are append-only and named by publish time, so reports for different archive
series never overwrite each other (e.g. a failed home backup is not masked by a later
successful system backup). The namespace is bounded by ``borg monitor --keep=N``, which
deletes all but the N newest objects.
"""

import json
import logging
import os
import time
from binascii import hexlify
from getpass import getuser

from borgstore.store import ItemInfo
from borgstore.store import ObjectNotFound as StoreObjectNotFound

from . import __version__
from . import platform
from .constants import EXIT_SUCCESS, EXIT_WARNING, EXIT_WARNING_BASE, EXIT_SIGNAL_BASE
from .crypto import monitoring as mon_crypto
from .helpers import bin_to_hex, get_ec
from .helpers.time import archive_ts_now

logger = logging.getLogger(__name__)

STORE_NAMESPACE = "monitoring"

# Default number of newest report objects to keep when running "borg monitor".
DEFAULT_KEEP = 500


def _new_object_name():
    """A unique, chronologically sortable object name.

    Microseconds since the epoch, zero-padded to a fixed width so lexical sort equals
    chronological order, plus a random suffix so same-microsecond or concurrent publishes
    never collide (and never overwrite an existing report).
    """
    us = int(time.time() * 1_000_000)
    return f"{us:020d}.{hexlify(os.urandom(4)).decode('ascii')}"


FORMAT_VERSION = 1
BODY_PLAIN = 0
BODY_SEALED = 1


def status_from_rc(rc):
    """Map a borg return code to a coarse status string.

    See constants.py: 0 = success, 1 = generic warning, 100..127 = specific warnings,
    everything else (generic/specific errors, signals) = error.
    """
    if rc == EXIT_SUCCESS:
        return "success"
    if rc == EXIT_WARNING or EXIT_WARNING_BASE <= rc < EXIT_SIGNAL_BASE:
        return "warning"
    return "error"


def build_report(
    *, command, repo_id, time, rc, hostname=None, username=None, archive=None, archive_id=None, stats=None
):
    """Assemble the report dict. *repo_id*/*archive_id* are hex strings, *time* is ISO."""
    report = {
        "borg_version": __version__,
        "repo_id": repo_id,
        "command": command,
        "time": time,
        "status": status_from_rc(rc),
        "rc": rc,
    }
    if hostname is not None:
        report["hostname"] = hostname
    if username is not None:
        report["username"] = username
    if archive is not None:
        report["archive"] = archive
    if archive_id is not None:
        report["archive_id"] = archive_id
    if stats is not None:
        report["stats"] = stats
    return report


def serialize(key, repo_id_bin, report):
    """Serialize *report* into the on-disk object bytes, sealing it if the repo is encrypted."""
    payload = json.dumps(report, sort_keys=True).encode("utf-8")
    if mon_crypto.is_signed_repo(key):
        body = mon_crypto.seal_report(key, payload, repo_id_bin)
        body_type = BODY_SEALED
    else:
        body = payload
        body_type = BODY_PLAIN
    return bytes([FORMAT_VERSION, body_type]) + body


def deserialize(monitor_key, repo_id_bin, data):
    """Return (report_dict, trusted: bool).

    *monitor_key* is the parsed (ed25519_public, hpke_secret) tuple, or None. A sealed
    report is verified+decrypted (trusted=True); a plaintext report is returned as-is
    (trusted=False). Raises ValueError/IntegrityError on malformed or unverifiable data.
    """
    if len(data) < 2 or data[0] != FORMAT_VERSION:
        raise ValueError("monitoring report: unsupported format version")
    body_type, body = data[1], data[2:]
    if body_type == BODY_SEALED:
        if monitor_key is None:
            raise ValueError("monitoring report is sealed but no BORG_MONITORING_KEY was given")
        ed_public, hpke_secret = monitor_key
        payload = mon_crypto.open_report(ed_public, hpke_secret, body, repo_id_bin)
        trusted = True
    elif body_type == BODY_PLAIN:
        payload = body
        trusted = False
    else:
        raise ValueError("monitoring report: unknown body type")
    return json.loads(payload.decode("utf-8")), trusted


def publish(repository, key, report):
    """Append *report* to the repository as a new object. Best-effort: never raise out."""
    try:
        data = serialize(key, repository.id, report)
        repository.store_store(f"{STORE_NAMESPACE}/{_new_object_name()}", data)
    except Exception as exc:
        logger.warning("Could not publish monitoring report: %s", exc)


def publish_command_report(
    repository, key, command, *, hostname=None, username=None, archive=None, archive_id=None, stats=None
):
    """Build and publish a report for a finished command.

    Captures the best-known return code at call time (the true process rc is only final
    after the store is closed; see borg/monitoring.py). Call this as the last action while
    the store is still open. *archive_id* is binary; it is hex-encoded for the report.
    *hostname*/*username* default to the local host and user (e.g. for repo-wide commands
    like prune); callers with an archive should pass the archive's own host/user.
    """
    report = build_report(
        command=command,
        repo_id=bin_to_hex(repository.id),
        time=archive_ts_now().isoformat(timespec="microseconds"),
        rc=get_ec(),
        hostname=hostname if hostname is not None else platform.hostname,
        username=username if username is not None else getuser(),
        archive=archive,
        archive_id=bin_to_hex(archive_id) if archive_id is not None else None,
        stats=stats,
    )
    publish(repository, key, report)


def list_names(repository):
    """Return all monitoring object names, oldest first (names sort chronologically)."""
    names = [ItemInfo(*info).name for info in repository.store_list(STORE_NAMESPACE)]
    names.sort()
    return names


def iter_reports(repository, monitor_key):
    """Yield (report, trusted) for every stored report, oldest first.

    Each report is verified and decrypted; an unverifiable one raises (it is not silently
    skipped) so tampering surfaces.
    """
    for name in list_names(repository):
        try:
            data = repository.store_load(f"{STORE_NAMESPACE}/{name}")
        except StoreObjectNotFound:
            continue  # raced with a concurrent --keep cleanup
        yield deserialize(monitor_key, repository.id, data)


def prune_reports(repository, keep):
    """Delete all but the *keep* newest report objects. Best-effort; returns #deleted.

    Needs delete permission on the monitoring namespace; on a permission error (e.g. a
    read-only monitoring host) it warns and stops rather than failing the command.
    """
    if keep is None or keep <= 0:
        return 0  # 0 (or negative) disables cleanup
    names = list_names(repository)
    to_delete = names[:-keep]
    deleted = 0
    for name in to_delete:
        try:
            repository.store_delete(f"{STORE_NAMESPACE}/{name}")
            deleted += 1
        except StoreObjectNotFound:
            pass  # already gone (concurrent cleanup)
        except Exception as exc:
            logger.warning("Could not delete old monitoring report %s: %s", name, exc)
            break  # likely missing delete permission; do not hammer the server
    return deleted
