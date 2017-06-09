import os
import sys
from binascii import unhexlify

from ..helpers import get_security_dir
from ..helpers import bin_to_hex
from ..platform import SaveFile
from ..remote import InvalidRPCMethod

from .low_level import bytes_to_long, long_to_bytes

MAX_REPRESENTABLE_NONCE = 2**64 - 1
NONCE_SPACE_RESERVATION = 2**28  # This in units of AES blocksize (16 bytes)


class NonceManager:
    def __init__(self, repository, enc_cipher, manifest_nonce):
        self.repository = repository
        self.enc_cipher = enc_cipher
        self.end_of_nonce_reservation = None
        self.manifest_nonce = manifest_nonce
        self.nonce_file = os.path.join(get_security_dir(self.repository.id_str), 'nonce')

    def get_local_free_nonce(self):
        try:
            with open(self.nonce_file, 'r') as fd:
                return bytes_to_long(unhexlify(fd.read()))
        except FileNotFoundError:
            return None

    def commit_local_nonce_reservation(self, next_unreserved, start_nonce):
        if self.get_local_free_nonce() != start_nonce:
            raise Exception("nonce space reservation with mismatched previous state")
        with SaveFile(self.nonce_file, binary=False) as fd:
            fd.write(bin_to_hex(long_to_bytes(next_unreserved)))

    def get_repo_free_nonce(self):
        try:
            return self.repository.get_free_nonce()
        except InvalidRPCMethod as error:
            # old server version, suppress further calls
            sys.stderr.write("Please upgrade to borg version 1.1+ on the server for safer AES-CTR nonce handling.\n")
            self.get_repo_free_nonce = lambda: None
            self.commit_repo_nonce_reservation = lambda next_unreserved, start_nonce: None
            return None

    def commit_repo_nonce_reservation(self, next_unreserved, start_nonce):
        self.repository.commit_nonce_reservation(next_unreserved, start_nonce)

    def ensure_reservation(self, nonce_space_needed):
        # Nonces may never repeat, even if a transaction aborts or the system crashes.
        # Therefore a part of the nonce space is reserved before any nonce is used for encryption.
        # As these reservations are committed to permanent storage before any nonce is used, this protects
        # against nonce reuse in crashes and transaction aborts. In that case the reservation still
        # persists and the whole reserved space is never reused.
        #
        # Local storage on the client is used to protect against an attacker that is able to rollback the
        # state of the server or can do arbitrary modifications to the repository.
        # Storage on the server is used for the multi client use case where a transaction on client A is
        # aborted and later client B writes to the repository.
        #
        # This scheme does not protect against attacker who is able to rollback the state of the server
        # or can do arbitrary modifications to the repository in the multi client usecase.

        if self.end_of_nonce_reservation:
            # we already got a reservation, if nonce_space_needed still fits everything is ok
            next_nonce = int.from_bytes(self.enc_cipher.iv, byteorder='big')
            assert next_nonce <= self.end_of_nonce_reservation
            if next_nonce + nonce_space_needed <= self.end_of_nonce_reservation:
                return

        repo_free_nonce = self.get_repo_free_nonce()
        local_free_nonce = self.get_local_free_nonce()
        free_nonce_space = max(x for x in (repo_free_nonce, local_free_nonce, self.manifest_nonce, self.end_of_nonce_reservation) if x is not None)
        reservation_end = free_nonce_space + nonce_space_needed + NONCE_SPACE_RESERVATION
        assert reservation_end < MAX_REPRESENTABLE_NONCE
        if self.end_of_nonce_reservation is None:
            # initialization, reset the encryption cipher to the start of the reservation
            self.enc_cipher.reset(None, free_nonce_space.to_bytes(16, byteorder='big'))
        else:
            # expand existing reservation if possible
            if free_nonce_space != self.end_of_nonce_reservation:
                # some other client got an interleaved reservation, skip partial space in old reservation to avoid overlap
                self.enc_cipher.reset(None, free_nonce_space.to_bytes(16, byteorder='big'))
        self.commit_repo_nonce_reservation(reservation_end, repo_free_nonce)
        self.commit_local_nonce_reservation(reservation_end, local_free_nonce)
        self.end_of_nonce_reservation = reservation_end
