import json

from ...constants import *  # NOQA
from . import cmd, RK_ENCRYPTION


def test_benchmark_crud(archiver, monkeypatch):
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("_BORG_BENCHMARK_CRUD_TEST", "YES")
    output = cmd(archiver, "benchmark", "crud", archiver.input_path)
    # Verify human-readable output contains expected C/R/U/D lines with MB/s
    for prefix in ("C-Z-TEST", "R-Z-TEST", "U-Z-TEST", "D-Z-TEST", "C-R-TEST", "R-R-TEST", "U-R-TEST", "D-R-TEST"):
        assert prefix in output
    assert "MB/s" in output


def test_benchmark_crud_json_lines(archiver, monkeypatch):
    cmd(archiver, "repo-create", RK_ENCRYPTION)
    monkeypatch.setenv("_BORG_BENCHMARK_CRUD_TEST", "YES")
    output = cmd(archiver, "benchmark", "crud", "--json-lines", archiver.input_path)
    # Filter for JSON lines only; the test harness merges stdout and stderr,
    # so non-JSON messages (e.g. "Done. Run borg compact...") from inner
    # commands may appear in the captured output.
    lines = [line for line in output.splitlines() if line.strip().startswith("{")]
    # 2 test samples (Z-TEST, R-TEST) x 4 operations (C, R, U, D) = 8 lines
    assert len(lines) == 8
    entries = [json.loads(line) for line in lines]
    # Verify all expected id values are present
    expected_ids = {"C-Z-TEST", "R-Z-TEST", "U-Z-TEST", "D-Z-TEST", "C-R-TEST", "R-R-TEST", "U-R-TEST", "D-R-TEST"}
    actual_ids = {e["id"] for e in entries}
    assert actual_ids == expected_ids
    for entry in entries:
        assert isinstance(entry["id"], str)
        assert entry["command"] in ("create1", "extract", "create2", "delete")
        assert isinstance(entry["sample"], str)
        assert entry["sample"] in ("Z-TEST", "R-TEST")
        assert isinstance(entry["sample_count"], int)
        assert entry["sample_count"] == 1
        assert isinstance(entry["sample_size"], int)
        assert entry["sample_size"] == 1
        assert isinstance(entry["sample_random"], bool)
        assert isinstance(entry["time"], float)
        assert entry["time"] > 0
        assert isinstance(entry["io"], int)
        assert entry["io"] > 0


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
