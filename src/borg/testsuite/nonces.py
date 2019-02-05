import os.path

import pytest

from ..crypto import nonces
from ..crypto.nonces import NonceManager
from ..crypto.key import bin_to_hex
from ..helpers import get_security_dir


class TestNonceManager:

    class MockRepository:
        class _Location:
            orig = '/some/place'

        location = _Location()
        id = bytes(32)
        id_str = bin_to_hex(id)

        def get_free_nonce(self):
            return self.next_free

        def commit_nonce_reservation(self, next_unreserved, start_nonce):
            assert start_nonce == self.next_free
            self.next_free = next_unreserved

    class MockOldRepository(MockRepository):
        def get_free_nonce(self):
            return None

        def commit_nonce_reservation(self, next_unreserved, start_nonce):
            return None

    def setUp(self):
        self.repository = None

    def cache_nonce(self):
        with open(os.path.join(get_security_dir(self.repository.id_str), 'nonce'), "r") as fd:
            return fd.read()

    def set_cache_nonce(self, nonce):
        with open(os.path.join(get_security_dir(self.repository.id_str), 'nonce'), "w") as fd:
            assert fd.write(nonce)

    def test_empty_cache_and_old_server(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockOldRepository()
        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x2000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"

    def test_empty_cache(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x2000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"

    def test_empty_nonce(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockRepository()
        self.repository.next_free = None
        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x2000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # enough space in reservation
        next_nonce = manager.ensure_reservation(0x2013, 13)
        assert next_nonce == 0x2013
        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # just barely enough space in reservation
        next_nonce = manager.ensure_reservation(0x2020, 19)
        assert next_nonce == 0x2020
        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # no space in reservation
        next_nonce = manager.ensure_reservation(0x2033, 16)
        assert next_nonce == 0x2033
        assert self.cache_nonce() == "0000000000002063"
        assert self.repository.next_free == 0x2063

        # spans reservation boundary
        next_nonce = manager.ensure_reservation(0x2043, 64)
        assert next_nonce == 0x2063
        assert self.cache_nonce() == "00000000000020c3"
        assert self.repository.next_free == 0x20c3

    def test_sync_nonce(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x2000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_server_just_upgraded(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockRepository()
        self.repository.next_free = None
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x2000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_transaction_abort_no_cache(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000

        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x1000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_transaction_abort_old_server(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockOldRepository()
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x1000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"

    def test_transaction_abort_on_other_client(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        self.set_cache_nonce("0000000000001000")

        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x1000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

    def test_interleaved(self, monkeypatch):
        monkeypatch.setattr(nonces, 'NONCE_SPACE_RESERVATION', 0x20)

        self.repository = self.MockRepository()
        self.repository.next_free = 0x2000
        self.set_cache_nonce("0000000000002000")

        manager = NonceManager(self.repository, 0x2000)
        next_nonce = manager.ensure_reservation(0x2000, 19)
        assert next_nonce == 0x2000

        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x2033

        # somehow the clients unlocks, another client reserves and this client relocks
        self.repository.next_free = 0x4000

        # enough space in reservation
        next_nonce = manager.ensure_reservation(0x2013, 12)
        assert next_nonce == 0x2013
        assert self.cache_nonce() == "0000000000002033"
        assert self.repository.next_free == 0x4000

        # spans reservation boundary
        next_nonce = manager.ensure_reservation(0x201f, 21)
        assert next_nonce == 0x4000
        assert self.cache_nonce() == "0000000000004035"
        assert self.repository.next_free == 0x4035
