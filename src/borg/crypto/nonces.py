import os
import sys

from ..helpers import Error
from ..helpers import get_security_dir
from ..helpers import bin_to_hex, hex_to_bin
from ..platform import SaveFile
from ..remote import InvalidRPCMethod

from .low_level import bytes_to_long, long_to_bytes

MAX_REPRESENTABLE_NONCE = 2**64 - 1
NONCE_SPACE_RESERVATION = 2**28  # This is in units of AES block size (16 bytes)


class NonceManager:
    def __init__(self, repository, manifest_nonce):
        self.repository = repository
        self.end_of_nonce_reservation = None
        self.manifest_nonce = manifest_nonce
        self.nonce_file = os.path.join(get_security_dir(self.repository.id_str), 'nonce')

    def get_local_free_nonce(self):
        try:
            with open(self.nonce_file) as fd:
                nonce_hex = fd.read().strip()
        except FileNotFoundError:
            return None
        else:
            try:
                nonce_bytes = hex_to_bin(nonce_hex, length=8)
            except ValueError as e:
                raise Error(f"Local security dir has an invalid nonce file: {e}") from None
            return bytes_to_long(nonce_bytes)

    def commit_local_nonce_reservation(self, next_unreserved, start_nonce):
        if self.get_local_free_nonce() != start_nonce:
            raise Exception("nonce space reservation with mismatched previous state")
        with SaveFile(self.nonce_file, binary=False) as fd:
            fd.write(bin_to_hex(long_to_bytes(next_unreserved)))

    def get_repo_free_nonce(self):
        try:
            return self.repository.get_free_nonce()
        except InvalidRPCMethod:
            # old server version, suppress further calls
            sys.stderr.write("Please upgrade to borg version 1.1+ on the server for safer AES-CTR nonce handling.\n")
            self.get_repo_free_nonce = lambda: None
            self.commit_repo_nonce_reservation = lambda next_unreserved, start_nonce: None
            return None

    def commit_repo_nonce_reservation(self, next_unreserved, start_nonce):
        self.repository.commit_nonce_reservation(next_unreserved, start_nonce)

    def ensure_reservation(self, nonce, nonce_space_needed):
        """
        Call this before doing encryption; give the current, yet unused, integer IV as <nonce>
        and the amount of subsequent (counter-like) IVs needed as <nonce_space_needed>.
        The return value is the IV (counter) integer you should use for encryption.

        Note: This method may return the <nonce> you gave if a reservation for it exists or
              can be established, so make sure you give an unused nonce.
        """
        # Nonces may never repeat, even if a transaction aborts or the system crashes.
        # Therefore a part of the nonce space is reserved before any nonce is used for encryption.
        # As these reservations are committed to permanent storage before any nonce is used, this protects
        # against nonce reuse in crashes and transaction aborts. In that case the reservation still
        # persists and the whole reserved space is never reused.
        #
        # Local storage on the client is used to protect against an attacker that is able to roll back the
        # state of the server or can do arbitrary modifications to the repository.
        # Storage on the server is used for the multi-client use case where a transaction on client A is
        # aborted and later client B writes to the repository.
        #
        # This scheme does not protect against an attacker who is able to roll back the state of the server
        # or can do arbitrary modifications to the repository in the multi-client use case.

        if self.end_of_nonce_reservation:
            # We already have a reservation; if nonce_space_needed still fits, everything is okay.
            next_nonce = nonce
            assert next_nonce <= self.end_of_nonce_reservation
            if next_nonce + nonce_space_needed <= self.end_of_nonce_reservation:
                return next_nonce

        repo_free_nonce = self.get_repo_free_nonce()
        local_free_nonce = self.get_local_free_nonce()
        free_nonce_space = max(x for x in (repo_free_nonce, local_free_nonce, self.manifest_nonce, self.end_of_nonce_reservation) if x is not None)
        reservation_end = free_nonce_space + nonce_space_needed + NONCE_SPACE_RESERVATION
        assert reservation_end < MAX_REPRESENTABLE_NONCE
        self.commit_repo_nonce_reservation(reservation_end, repo_free_nonce)
        self.commit_local_nonce_reservation(reservation_end, local_free_nonce)
        self.end_of_nonce_reservation = reservation_end
        return free_nonce_space
