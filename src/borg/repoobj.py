import os
from collections import namedtuple
from struct import Struct

from .constants import *  # NOQA
from .helpers import msgpack, workarounds
from .helpers.errors import Error, IntegrityError
from .compress import Compressor, LZ4_COMPRESSOR
from .crypto.low_level import IntegrityError as IntegrityErrorBase

# Workaround for lost passphrase or key in the "authenticated-*" modes
AUTHENTICATED_NO_KEY = "authenticated_no_key" in workarounds

# The places where parse() verifies chunkid == id_hash(content) only if the user asks for it.
# The user picks the places via BORG_ASSERT_ID (comma-separated), see the docs of that env var.
ASSERT_ID_PLACES = (
    "read",  # the general read path: extract, mount, export-tar, diff, ...
    "repair",  # borg check --repair
    "transfer",  # borg transfer (everything it reads from the source repo)
    "rechunk",  # borg recreate --chunker-params (re-chunking reads)
)
# The places that always verify and thus can not be configured: borg check --verify-data is the
# audit that re-certifies the id/content invariant for all chunks of a repository - it is what makes
# not verifying elsewhere defensible, so it must not be switchable.
ASSERT_ID_PLACES_MANDATORY = ("verify_data",)  # borg check --verify-data
# Default value of the BORG_ASSERT_ID env var: verify everywhere except on the (hot) general read
# path - there, the envelope authentication of the keyed modes already covers what a repository
# could do to us, see AEADKeyBase.assert_id. (For the modes whose id check *is* the read path
# authentication, this setting does not apply, see below.)
BORG_ASSERT_ID_DEFAULT = ("repair", "transfer", "rechunk")
# Reads through a RepoObj are attributed to this place unless a command sets another one.
ASSERT_ID_PLACE_DEFAULT = "read"


def get_assert_id_places():
    """Determine the configurable places that shall verify the chunk id, see the BORG_ASSERT_ID docs.

    Note: this only decides for keys that authenticate reads independently of the id hash (the AEAD
    ciphersuites and the "authenticated-*" modes, see KeyBase.id_check_is_authentication) - for all
    other keys, the id check is the read path authentication itself and thus always happens, no
    matter what is configured here.
    The same is true for ASSERT_ID_PLACES_MANDATORY.
    """
    value = os.environ.get("BORG_ASSERT_ID")
    if value is None:
        return frozenset(BORG_ASSERT_ID_DEFAULT)
    places = frozenset(place.strip() for place in value.split(",") if place.strip())
    invalid = places - set(ASSERT_ID_PLACES)
    if invalid:
        problems = []
        mandatory = sorted(invalid & set(ASSERT_ID_PLACES_MANDATORY))
        if mandatory:
            problems.append(f"{', '.join(mandatory)}: always verifies, can not be configured")
        unknown = sorted(invalid - set(ASSERT_ID_PLACES_MANDATORY))
        if unknown:
            problems.append(f"{', '.join(unknown)}: invalid place name(s)")
        raise Error(f"BORG_ASSERT_ID: {'; '.join(problems)}. Valid place names are: {', '.join(ASSERT_ID_PLACES)}.")
    return places


OBJ_MAGIC = b"BORG_OBJ"

# meta_encrypted/data_encrypted are AEAD-authenticated with aad=chunk_id.
OBJ_VERSION_NO_HEADER_AAD = 0x01
# meta_encrypted/data_encrypted are AEAD-authenticated with aad=header_aad+slot_tag+chunk_id. header_aad
# is the header prefix (magic, version, chunk_id; REPOOBJ_HEADER_AAD_SIZE bytes). slot_tag is b"M" for
# meta_encrypted, b"D" for data_encrypted, binding each ciphertext to its slot. format() writes this version.
OBJ_VERSION_HEADER_AAD = 0x02
OBJ_VERSION = OBJ_VERSION_HEADER_AAD
# Versions accepted by parse() and parse_meta().
SUPPORTED_OBJ_VERSIONS = (OBJ_VERSION_NO_HEADER_AAD, OBJ_VERSION_HEADER_AAD)

# Fixed header size per blob: OBJ_MAGIC(8) + version(1) + chunk_id(32) + meta_size(4) + data_size(4)
REPOOBJ_HEADER_SIZE = 49

# Size of the header prefix used as AEAD AAD (additional authenticated data: authenticated together
# with the ciphertext, but not itself encrypted) for OBJ_VERSION_HEADER_AAD objects: magic(8) +
# version(1) + chunk_id(32). meta_size and data_size are excluded, since they are only known after
# encryption. A change to either changes the ciphertext slice length, so parse(), which reads both
# slots, fails authentication; parse_meta() reads the metadata slot alone and thus does not see a
# changed data_size.
REPOOBJ_HEADER_AAD_SIZE = len(OBJ_MAGIC) + 1 + 32

META_AAD_TAG = b"M"
DATA_AAD_TAG = b"D"


class RepoObj:
    # Object header: magic (8b), format version (1b), chunk_id (32b), meta size (4b), data size (4b).
    obj_header = Struct("<8sB32sII")
    ObjHeader = namedtuple("ObjHeader", "magic version chunk_id meta_size data_size")

    @classmethod
    def extract_crypted_data(cls, data: bytes) -> bytes:
        # used for crypto type detection
        hdr_size = cls.obj_header.size
        if len(data) < hdr_size:
            raise IntegrityError(f"object too small: expected at least {hdr_size} header bytes, got {len(data)}")
        hdr = cls.ObjHeader(*cls.obj_header.unpack(data[:hdr_size]))
        if hdr.magic != OBJ_MAGIC:
            raise IntegrityError("invalid object magic")
        if hdr.version not in SUPPORTED_OBJ_VERSIONS:
            raise IntegrityError(f"unsupported object version: {hdr.version}")
        overall_expected_size = hdr_size + hdr.meta_size + hdr.data_size
        if overall_expected_size != len(data):
            raise IntegrityError(f"object size inconsistent: expected {overall_expected_size} bytes, got {len(data)}")
        return data[hdr_size + hdr.meta_size :]  # crypted data

    def __init__(self, key):
        self.key = key
        # Some commands write new chunks (e.g. rename) but don't take a --compression argument. This duplicates
        # the default used by those commands who do take a --compression argument.
        self.compressor = LZ4_COMPRESSOR
        # Where shall the chunk id be verified over the plaintext? See parse() and the BORG_ASSERT_ID docs.
        self.assert_id_places = get_assert_id_places()
        # The place reads through this RepoObj are attributed to. Commands that are a trust boundary for
        # the id/content invariant (transfer, re-chunking, check --repair) set their own place, see
        # set_assert_id_place.
        self.assert_id_place = ASSERT_ID_PLACE_DEFAULT

    def set_assert_id_place(self, place: str) -> None:
        """Attribute all reads through this RepoObj to <place>, see the BORG_ASSERT_ID docs."""
        assert place in ASSERT_ID_PLACES + ASSERT_ID_PLACES_MANDATORY
        self.assert_id_place = place

    def id_hash(self, data: bytes) -> bytes:
        return self.key.id_hash(data)

    def format(
        self,
        id: bytes,
        meta: dict,
        data: bytes,
        compress: bool = True,
        size: int = None,
        ctype: int = None,
        clevel: int = None,
        ro_type: str = None,
    ) -> bytes:
        assert isinstance(ro_type, str)
        assert ro_type != ROBJ_DONTCARE
        meta["type"] = ro_type
        assert isinstance(id, bytes)
        assert len(id) == 32  # struct format "32s" silently pads/truncates a wrong-length id
        assert isinstance(meta, dict)
        assert isinstance(data, (bytes, memoryview))
        assert compress or size is not None and ctype is not None and clevel is not None
        if compress:
            assert size is None or size == len(data)
            meta, data_compressed = self.compressor.compress(meta, data)
        else:
            assert isinstance(size, int)
            meta["size"] = size
            assert isinstance(ctype, int)
            meta["ctype"] = ctype
            assert isinstance(clevel, int)
            meta["clevel"] = clevel
            data_compressed = data  # is already compressed, is NOT prefixed by type/level bytes
            meta["csize"] = len(data_compressed)
        header_aad = OBJ_MAGIC + bytes([OBJ_VERSION]) + id
        data_encrypted = self.key.encrypt(id, data_compressed, aad=header_aad + DATA_AAD_TAG)
        meta_packed = msgpack.packb(meta)
        meta_encrypted = self.key.encrypt(id, meta_packed, aad=header_aad + META_AAD_TAG)
        hdr = self.ObjHeader(OBJ_MAGIC, OBJ_VERSION, id, len(meta_encrypted), len(data_encrypted))
        hdr_packed = self.obj_header.pack(*hdr)
        return hdr_packed + meta_encrypted + data_encrypted

    def parse_meta(self, id: bytes, cdata: bytes | memoryview, ro_type: str) -> dict:
        # when calling parse_meta, enough cdata needs to be supplied to contain completely the
        # meta_len_hdr and the encrypted, packed metadata. it is allowed to provide more cdata.
        assert isinstance(id, bytes)
        assert isinstance(cdata, (bytes, memoryview))
        assert isinstance(ro_type, str)
        obj = memoryview(cdata)
        hdr_size = self.obj_header.size
        if len(obj) < hdr_size:
            raise IntegrityError(f"object too small: expected at least {hdr_size} header bytes, got {len(obj)}")
        hdr = self.ObjHeader(*self.obj_header.unpack(obj[:hdr_size]))
        if hdr.magic != OBJ_MAGIC:
            raise IntegrityError("invalid object magic")
        if hdr.version not in SUPPORTED_OBJ_VERSIONS:
            raise IntegrityError(f"unsupported object version: {hdr.version}")
        if hdr_size + hdr.meta_size > len(obj):
            raise IntegrityError(
                f"object too small: expected at least {hdr_size + hdr.meta_size} bytes, got {len(obj)}"
            )
        # header_aad, meta_aad: see OBJ_VERSION_HEADER_AAD above. b"" for OBJ_VERSION_NO_HEADER_AAD.
        header_aad = bytes(obj[:REPOOBJ_HEADER_AAD_SIZE]) if hdr.version == OBJ_VERSION_HEADER_AAD else b""
        meta_aad = header_aad + META_AAD_TAG if hdr.version == OBJ_VERSION_HEADER_AAD else header_aad
        meta_encrypted = obj[hdr_size : hdr_size + hdr.meta_size]
        meta_packed = self.key.decrypt(id, meta_encrypted, aad=meta_aad)
        meta = msgpack.unpackb(meta_packed)
        if ro_type != ROBJ_DONTCARE and meta["type"] != ro_type:
            raise IntegrityError(f"ro_type expected: {ro_type} got: {meta['type']}")
        return meta

    def parse(
        self,
        id: bytes,
        cdata: bytes | memoryview,
        decompress: bool = True,
        want_compressed: bool = False,
        ro_type: str = None,
        assert_id_place: str = None,
    ) -> tuple[dict, bytes]:
        """
        Parse a repo object into metadata and data (decrypt it, maybe decompress, maybe verify if the chunk plaintext
        corresponds to the chunk id via assert_id()).

        Tweaking options (default is usually fine):
        - decompress=True, want_compressed=False: slow, verifying. returns decompressed data (default).
        - decompress=True, want_compressed=True: slow, verifying. returns compressed data (caller wants to reuse it).
        - decompress=False, want_compressed=True: quick, not verifying. returns compressed data (caller wants to reuse).
        - decompress=False, want_compressed=False: invalid

        assert_id_place gives the place this specific read happens at (see the BORG_ASSERT_ID docs); if not
        given, the RepoObj's place is used (see set_assert_id_place). Places in ASSERT_ID_PLACES_MANDATORY
        always verify, the others only if the user asked for them.
        """
        assert isinstance(ro_type, str)
        assert not (not decompress and not want_compressed), "invalid parameter combination!"
        assert isinstance(id, bytes)
        assert isinstance(cdata, (bytes, memoryview))
        obj = memoryview(cdata)
        hdr_size = self.obj_header.size
        if len(obj) < hdr_size:
            raise IntegrityError(f"object too small: expected at least {hdr_size} header bytes, got {len(obj)}")
        hdr = self.ObjHeader(*self.obj_header.unpack(obj[:hdr_size]))
        if hdr.magic != OBJ_MAGIC:
            raise IntegrityError("invalid object magic")
        if hdr.version not in SUPPORTED_OBJ_VERSIONS:
            raise IntegrityError(f"unsupported object version: {hdr.version}")
        overall_expected_size = hdr_size + hdr.meta_size + hdr.data_size
        if overall_expected_size != len(obj):
            raise IntegrityError(f"object size inconsistent: expected {overall_expected_size} bytes, got {len(obj)}")
        # header_aad, meta_aad: see parse_meta().
        header_aad = bytes(obj[:REPOOBJ_HEADER_AAD_SIZE]) if hdr.version == OBJ_VERSION_HEADER_AAD else b""
        meta_aad = header_aad + META_AAD_TAG if hdr.version == OBJ_VERSION_HEADER_AAD else header_aad
        data_aad = header_aad + DATA_AAD_TAG if hdr.version == OBJ_VERSION_HEADER_AAD else header_aad
        meta_encrypted = obj[hdr_size : hdr_size + hdr.meta_size]
        meta_packed = self.key.decrypt(id, meta_encrypted, aad=meta_aad)
        meta_compressed = msgpack.unpackb(meta_packed)  # means: before adding more metadata in decompress block
        if ro_type != ROBJ_DONTCARE and meta_compressed["type"] != ro_type:
            raise IntegrityError(f"ro_type expected: {ro_type} got: {meta_compressed['type']}")
        data_encrypted = obj[hdr_size + hdr.meta_size : hdr_size + hdr.meta_size + hdr.data_size]
        data_compressed = self.key.decrypt(id, data_encrypted, aad=data_aad)  # does not include type/level
        if decompress:
            ctype = meta_compressed["ctype"]
            clevel = meta_compressed["clevel"]
            csize = meta_compressed["csize"]  # always the overall size
            assert csize == len(data_compressed)
            psize = meta_compressed.get(
                "psize", csize
            )  # obfuscation: psize (payload size) is potentially less than csize.
            assert psize <= csize
            compr_hdr = bytes((ctype, clevel))
            compressor_cls, compression_level = Compressor.detect(compr_hdr)
            compressor = compressor_cls(level=compression_level)
            meta, data = compressor.decompress(dict(meta_compressed), data_compressed[:psize])
            # For keys where the id check is the read-path authentication (the "none-*" modes, whose
            # envelope checksum is unkeyed and thus no authentication), it always has to happen -
            # skipping it would remove all integrity checking from reads.
            # For the keys that authenticate the envelope (the AEAD and the "authenticated-*" modes), the
            # payload is already authenticated for this specific chunk id (the id is in the AAD), so the id
            # check only adds detection of chunks whose plaintext does not match their id - which only an
            # evil/broken borg client that had the repo key could have written. Whether that extra
            # full-plaintext hash pass is worth it depends on the place we read at, see BORG_ASSERT_ID.
            place = assert_id_place if assert_id_place is not None else self.assert_id_place
            assert_id = (
                self.key.id_check_is_authentication
                or place in ASSERT_ID_PLACES_MANDATORY
                or place in self.assert_id_places
            )
            # the authenticated_no_key workaround fakes key material it could not unlock, so checks that
            # need that key material can not work. The unkeyed modes need none, so they keep checking.
            if assert_id and not (AUTHENTICATED_NO_KEY and self.key.has_secret_key):
                self.key.assert_id(id, data)
        else:
            meta, data = None, None
        return meta_compressed if want_compressed else meta, data_compressed if want_compressed else data


def object_validator(repo_objs):
    """Return validate(chunk_id, obj): True if obj is the repo object with id chunk_id.

    obj is an object's header plus its metadata slot. Parsing that slot verifies its tag, which is
    computed over the slot itself and over the chunk id, so a wrong meta_size or chunk id fails it.
    At object version OBJ_VERSION_HEADER_AAD the magic and the version are covered as well (as AAD,
    additional authenticated data: bytes the tag covers without being part of the ciphertext); at
    OBJ_VERSION_NO_HEADER_AAD they are not: a wrong magic fails the explicit magic check, and a
    wrong version fails because the version selects the AAD the slot is parsed with. data_size, the
    one header field outside the tag at either version, must match csize - the data slot's payload
    size, recorded in the tagged metadata - plus the key's fixed envelope overhead.

    In the "none-*" modes the tag is an unkeyed checksum, and in the "authenticated-*" modes it is
    deterministic and binds an object to its chunk id alone. Both therefore accept an object that a
    backed up file contains, at any offset in any pack.
    """
    hdr_size = RepoObj.obj_header.size
    overhead = repo_objs.key.PAYLOAD_OVERHEAD  # the envelope adds a fixed number of bytes to the payload

    def validate(chunk_id, obj):
        try:
            meta = repo_objs.parse_meta(chunk_id, obj, ro_type=ROBJ_DONTCARE)
        except (IntegrityErrorBase, msgpack.UnpackException):
            # arbitrary bytes fail the authentication, or the msgpack unpacking in the modes that
            # authenticate without a secret key (none-*, authenticated-*) and thus accept them.
            return False
        # in those modes the metadata slot can therefore unpack to any value. Inspect the value
        # rather than catching what using it raises, so that only unusable metadata gives False
        # and an unexpected exception still reaches the caller.
        if not isinstance(meta, dict):
            return False
        csize = meta.get("csize")
        if not isinstance(csize, int) or isinstance(csize, bool):  # msgpack unpacks true/false to bool
            return False
        data_size = RepoObj.ObjHeader(*RepoObj.obj_header.unpack(obj[:hdr_size])).data_size
        return data_size == csize + overhead

    return validate


# Backward compatibility: RepoObj1 has moved to borg.legacy.repoobj
from .legacy.repoobj import RepoObj1  # noqa: F401
