import pytest
import time
import types
from unittest.mock import MagicMock
# Importamos el módulo donde está la lógica original
import borg.repository 

# 1. Definimos los Mocks que el código necesita para no romperse
class MockRepoObj:
    class ObjHeader:
        def __init__(self, *args):
            self.meta_size = 0
            self.data_size = 0
            self.meta_hash = b'hash'
            self.data_hash = b'hash'
    obj_header = MagicMock()
    obj_header.size = 8
    # Esto simula el unpack de struct para obtener meta_size, data_size, etc.
    obj_header.unpack = MagicMock(return_value=(0, 0, b'hash', b'hash'))

def mock_xxh64(data): return b'hash'

# 2. FakeStore para simular la base de datos de Borg
class FakeStore:
    def __init__(self, objects=None):
        self.objects = objects or {}
        self.deleted = []
        self.stored = {}

    def list(self, prefix):
        return [types.SimpleNamespace(name=k.split("/", 1)[1]) 
                for k in sorted(self.objects.keys())]

    def load(self, key):
        if key not in self.objects:
            from borg.repository import StoreObjectNotFound
            raise StoreObjectNotFound
        return self.objects[key]

    def delete(self, key):
        self.deleted.append(key)
        self.objects.pop(key, None)

    def store(self, key, value):
        self.stored[key] = value

# --- EL TEST CORREGIDO ---

def test_check_repair_deletes_corrupt_object(caplog, monkeypatch):
    # Usamos monkeypatch.setattr para inyectar los mocks en el módulo correcto
    monkeypatch.setattr(borg.repository, "RepoObj", MockRepoObj)
    monkeypatch.setattr(borg.repository, "xxh64", mock_xxh64)
    # Mockeamos el logger para que no intente escribir en archivos reales
    mock_logger = MagicMock()
    monkeypatch.setattr(borg.repository, "logger", mock_logger)
    
    # Preparamos el Store con un objeto que fallará (demasiado pequeño)
    good_id = "0" * 64 
    store = FakeStore(objects={f"data/{good_id}": b"fail"}) # < 8 bytes (hdr_size)
    
    # Instanciamos el repositorio real o un mock con el método real
    repo = MagicMock(spec=borg.repository.Repository)
    repo.store = store
    # Forzamos el uso de la función original en nuestro mock
    repo.check = borg.repository.Repository.check.__get__(repo, borg.repository.Repository)
    repo._lock_refresh = MagicMock()

    # Ejecución
    with caplog.at_level("INFO"):
        # Importante: repair=True, max_duration=0 para evitar el conflicto del assert
        ok = repo.check(repair=True, max_duration=0)

    # Verificaciones
    assert ok is True
    assert f"data/{good_id}" in store.deleted
    mock_logger.error.assert_any_call(f"Repo object {good_id} is corrupted: too small.")