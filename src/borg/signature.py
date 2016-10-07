import json
import os
from hmac import compare_digest

from .crypto import StreamSigner_HMAC_SHA512_REPOID, FileLikeWrapper
from .helpers import bin_to_hex
from .helpers import Error
from .logger import create_logger
logger = create_logger()


class SignatureError(Error):
    """Invalid signature for {}"""


class SignedFile(FileLikeWrapper):
    # generic enough that it can be used without a KeyBase
    def __init__(self, key, path, write, filename=None, override_fd=None):
        self.path = path
        self.writing = write
        mode = 'wb' if write else 'rb'
        self.file_fd = override_fd or open(path, mode)
        self.signer = StreamSigner_HMAC_SHA512_REPOID(key, self.file_fd, write)
        self.fd = self.signer  # for FileLikeWrapper
        self.sign_filename(filename)
        if write:
            self.signatures = {}
        else:
            self.signatures = self.read_signatures(path, self.signer)

    def sign_filename(self, filename=None):
        # Sign the name of the file as well, but only the basename, ie. not the path. In Borg
        # the name itself encodes the context (eg. index.N, cache, files), while the path doesn't matter,
        # and moving eg. a repository or cache directory is supported.
        # Changing the name however imbues a change of context that is not permissible.
        filename = os.path.basename(filename or self.path)
        self.signer.update(str(len(filename)).encode())
        self.signer.update(filename.encode())

    @staticmethod
    def signature_path(path):
        return path + '.signature'

    @classmethod
    def read_signatures(cls, path, signer):
        try:
            with open(cls.signature_path(path), 'r') as fd:
                signature = json.load(fd)
                # Provisions for agility now, implementation later, but make sure the on-disk joint is oiled.
                algorithm = signature['algorithm']
                if algorithm != signer.NAME:
                    logger.warning('Cannot verify signature for %s: Unknown algorithm %r', path, algorithm)
                    return
                signatures = signature['signatures']
                # Require at least presence of the final signature
                signatures['final']
                return signatures
        except FileNotFoundError:
            logger.info('No signature found for %s', path)
        except (OSError, ValueError, TypeError, KeyError) as e:
            logger.warning('Could not read signature for %s: %s', path, e)
            raise SignatureError(path)

    def sign_part(self, partname, is_final=False):
        self.signer.update(partname.encode())
        self.signer.sign_length(seek_to_end=is_final)
        signature = bin_to_hex(self.signer.signature())
        if self.writing:
            self.signatures[partname] = signature
        elif self.signatures and not compare_digest(self.signatures.get(partname, ''), signature):
            raise SignatureError(self.path)

    def __exit__(self, exc_type, exc_val, exc_tb):
        exception = exc_type is not None
        if not exception:
            self.sign_part('final', is_final=True)
        self.signer.__exit__(exc_type, exc_val, exc_tb)
        if exception:
            return
        if self.writing:
            with open(self.signature_path(self.path), 'w') as fd:
                json.dump({
                    'algorithm': self.signer.NAME,
                    'signatures': self.signatures,
                }, fd)
        elif self.signatures:
            logger.debug('Verified signature of %s', self.path)
