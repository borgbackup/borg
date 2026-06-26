import binascii
import os
import pkgutil
import textwrap
from hashlib import sha256

from ..helpers import Error, CommandError, yes, bin_to_hex, hex_to_bin, dash_open, get_keys_dir
from ..repoobj import RepoObj


from .key import keyfile_format, keyfile_parse, is_keyfile
from .key import RepoKeyNotFoundError, KeyBlobStorage, KEY_LOCATIONS, identify_key, keyfile_name_for


class NotABorgKeyFile(Error):
    """This file is not a Borg key backup, aborting."""

    exit_mcode = 43


class RepoIdMismatch(Error):
    """This key backup seems to be for a different backup repository, aborting."""

    exit_mcode = 45


class UnencryptedRepo(Error):
    """Key management not available for unencrypted repositories."""

    exit_mcode = 46


class UnknownKeyType(Error):
    """Key type {0} is unknown."""

    exit_mcode = 47


def sha256_truncated(data, num):
    h = sha256()
    h.update(data)
    return h.hexdigest()[:num]


class KeyManager:
    def __init__(self, repository):
        self.repository = repository
        self.keyblob = None
        self.keyblob_storage = None
        # id / label of the borg key that load_keyblob() selected (for logging by the caller):
        self.loaded_key_id = None
        self.loaded_label = None

        manifest_chunk = repository.get_manifest()
        manifest_data = RepoObj.extract_crypted_data(manifest_chunk)
        self.key_cls = identify_key(manifest_data)
        self.keyblob_storage = self.key_cls.STORAGE
        if self.keyblob_storage == KeyBlobStorage.NO_STORAGE:
            raise UnencryptedRepo()

    def _list_borg_keys(self):
        # enumerate all borg keys of this repository together with their plaintext labels,
        # without unlocking them, reusing the same machinery as "borg key list".
        flexikey = self.key_cls(self.repository)
        result = []
        for key_id, blob_text, _keyfile_path in flexikey._iter_keys():
            if is_keyfile(blob_text):
                try:
                    _, b64 = keyfile_parse(blob_text, bin_to_hex(self.repository.id))
                except ValueError:
                    continue
            else:
                b64 = blob_text  # borg 1.x repokey: raw base64, no BORG_KEY header
            try:
                label = flexikey._key_envelope(blob_text).get("label")
            except Exception:  # noqa: BLE001 - best-effort: a borg key without a parseable envelope has no label
                label = None
            result.append({"id": key_id, "label": label, "b64": b64})
        return result

    def load_keyblob(self, *, label=None, key_id=None):
        candidates = self._list_borg_keys()
        if not candidates:
            loc = self.repository._location.canonical_path()
            raise RepoKeyNotFoundError(loc) from None
        if label is not None:
            matches = [c for c in candidates if c["label"] == label]
        elif key_id is not None:
            matches = [c for c in candidates if c["id"].startswith(key_id)]
        elif len(candidates) == 1:
            matches = candidates  # no selector needed when there is only one borg key
        else:
            labels = ", ".join(repr(c["label"]) for c in candidates)
            raise CommandError(
                "This repository has multiple borg keys (%s); "
                "select which one to export with --label or --key (see 'borg key list')." % labels
            )
        if len(matches) != 1:
            raise CommandError("The selector needs to match precisely 1 key, but it matched %d keys." % len(matches))
        selected = matches[0]
        self.keyblob = selected["b64"]
        self.loaded_key_id = selected["id"]
        self.loaded_label = selected["label"]

    def store_keyblob(self, args):
        # storage location for the imported key: --key-location wins, else the class default.
        storage = KEY_LOCATIONS.get(getattr(args, "key_location", None), self.keyblob_storage)
        if storage == KeyBlobStorage.KEYFILE:
            from .key import CHPOKey

            k = CHPOKey(self.repository)
            target = k.get_existing_or_new_target(args)
            keyfile_data = self.get_keyfile_data()
            if not os.environ.get("BORG_KEY_FILE") and os.path.samefile(target, get_keys_dir()):
                target = os.path.join(target, keyfile_name_for(keyfile_data.encode()))
            with dash_open(target, "w") as fd:
                fd.write(keyfile_data)
        elif storage == KeyBlobStorage.REPO:
            key_data = keyfile_format(bin_to_hex(self.repository.id), self.keyblob.strip())
            self.repository.save_key(key_data.encode("utf-8"))

    def get_keyfile_data(self):
        return keyfile_format(bin_to_hex(self.repository.id), self.keyblob.strip())

    def store_keyfile(self, target):
        with dash_open(target, "w") as fd:
            fd.write(self.get_keyfile_data())

    def export(self, path):
        if path is None:
            path = "-"

        self.store_keyfile(path)

    def export_qr(self, path):
        if path is None:
            path = "-"

        with dash_open(path, "wb") as fd:
            key_data = self.get_keyfile_data()
            html = pkgutil.get_data("borg", "paperkey.html")
            html = html.replace(b"</textarea>", key_data.encode() + b"</textarea>")
            fd.write(html)

    def export_paperkey(self, path):
        if path is None:
            path = "-"

        def grouped(s):
            ret = ""
            i = 0
            for ch in s:
                if i and i % 6 == 0:
                    ret += " "
                ret += ch
                i += 1
            return ret

        export = "To restore key use borg key import --paper /path/to/repo\n\n"

        binary = binascii.a2b_base64(self.keyblob)
        export += "BORG PAPER KEY v1\n"
        lines = (len(binary) + 17) // 18
        repoid = bin_to_hex(self.repository.id)[:18]
        complete_checksum = sha256_truncated(binary, 12)
        export += "id: {:d} / {} / {} - {}\n".format(
            lines,
            grouped(repoid),
            grouped(complete_checksum),
            sha256_truncated((str(lines) + "/" + repoid + "/" + complete_checksum).encode("ascii"), 2),
        )
        idx = 0
        while len(binary):
            idx += 1
            binline = binary[:18]
            checksum = sha256_truncated(idx.to_bytes(2, byteorder="big") + binline, 2)
            export += f"{idx:2d}: {grouped(bin_to_hex(binline))} - {checksum}\n"
            binary = binary[18:]

        with dash_open(path, "w") as fd:
            fd.write(export)

    def import_keyfile(self, args):
        with dash_open(args.path, "r") as fd:
            key_data = fd.read()
        try:
            repoid, b64data = keyfile_parse(key_data, bin_to_hex(self.repository.id))
        except ValueError:
            if not is_keyfile(key_data):
                raise NotABorgKeyFile() from None
            raise RepoIdMismatch() from None
        self.keyblob = b64data
        self.store_keyblob(args)

    def import_paperkey(self, args):
        try:
            # imported here because it has global side effects
            import readline  # noqa
        except ImportError:
            print("Note: No line editing available due to missing readline support")

        repoid = bin_to_hex(self.repository.id)[:18]
        try:
            while True:  # used for repeating on overall checksum mismatch
                # id line input
                while True:
                    idline = input("id: ").replace(" ", "")
                    if idline == "":
                        if yes("Abort import? [yN]:"):
                            raise EOFError()

                    try:
                        (data, checksum) = idline.split("-")
                    except ValueError:
                        print("each line must contain exactly one '-', try again")
                        continue
                    try:
                        (id_lines, id_repoid, id_complete_checksum) = data.split("/")
                    except ValueError:
                        print("the id line must contain exactly two '/', try again")
                        continue
                    if sha256_truncated(data.lower().encode("ascii"), 2) != checksum:
                        print("line checksum did not match, try same line again")
                        continue
                    try:
                        lines = int(id_lines)
                    except ValueError:
                        print("internal error while parsing length")

                    break

                if repoid != id_repoid:
                    raise RepoIdMismatch()

                result = b""
                idx = 1
                # body line input
                while True:
                    inline = input(f"{idx:2d}: ")
                    inline = inline.replace(" ", "")
                    if inline == "":
                        if yes("Abort import? [yN]:"):
                            raise EOFError()
                    try:
                        (data, checksum) = inline.split("-")
                    except ValueError:
                        print("each line must contain exactly one '-', try again")
                        continue
                    try:
                        part = hex_to_bin(data)
                    except ValueError as e:
                        print(f"only characters 0-9 and a-f and '-' are valid, try again [{e}]")
                        continue
                    if sha256_truncated(idx.to_bytes(2, byteorder="big") + part, 2) != checksum:
                        print(f"line checksum did not match, try line {idx} again")
                        continue
                    result += part
                    if idx == lines:
                        break
                    idx += 1

                if sha256_truncated(result, 12) != id_complete_checksum:
                    print("The overall checksum did not match, retry or enter a blank line to abort.")
                    continue

                self.keyblob = "\n".join(textwrap.wrap(binascii.b2a_base64(result).decode("ascii"))) + "\n"
                self.store_keyblob(args)
                break

        except EOFError:
            print("\n - aborted")
            return
