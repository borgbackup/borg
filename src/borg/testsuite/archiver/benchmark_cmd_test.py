import json

from ...constants import *  # NOQA
from . import cmd, RK_ENCRYPTION


def test_benchmark_crud(archiver, monkeypatch):
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("_BORG_BENCHMARK_CRUD_TEST", "YES")
    cmd(archiver, "benchmark", "crud", archiver.input_path)


def test_benchmark_cpu(archiver):
    output = cmd(archiver, "benchmark", "cpu")
    # verify all section headers appear in the plain-text output
    assert "Chunkers" in output
    assert "Non-cryptographic checksums / hashes" in output
    assert "Cryptographic hashes / MACs" in output
    assert "Encryption" in output
    assert "KDFs" in output
    assert "Compression" in output
    assert "msgpack" in output


def test_benchmark_cpu_json(archiver):
    output = cmd(archiver, "benchmark", "cpu", "--json")
    result = json.loads(output)
    assert isinstance(result, dict)
    # categories with "size" field (bytes)
    for category in ["chunkers", "checksums", "hashes", "encryption"]:
        assert isinstance(result[category], list)
        assert len(result[category]) > 0
        for entry in result[category]:
            assert isinstance(entry["algo"], str)
            assert isinstance(entry["size"], int)
            assert isinstance(entry["time"], float)
    # chunkers and compression also have algo_params
    for category in ["chunkers", "compression"]:
        for entry in result[category]:
            assert "algo_params" in entry
    # categories with "count" field
    for category in ["kdf", "msgpack"]:
        assert isinstance(result[category], list)
        assert len(result[category]) > 0
        for entry in result[category]:
            assert isinstance(entry["algo"], str)
            assert isinstance(entry["count"], int)
            assert isinstance(entry["time"], float)
    # compression has size field too
    for entry in result["compression"]:
        assert isinstance(entry["size"], int)
