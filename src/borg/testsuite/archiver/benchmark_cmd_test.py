import json
import re

import pytest

from ...constants import *  # NOQA
from ...helpers import CommandError
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
        # io is int(bytes/second); with this test's 1-byte samples it is 0
        # whenever the operation takes >= 1s (seen on a loaded OpenBSD CI VM).
        assert entry["io"] >= 0


def test_benchmark_cpu(archiver, monkeypatch):
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    output = cmd(archiver, "benchmark", "cpu")
    # verify all section headers appear in the plain-text output
    assert "Chunkers" in output
    assert "Cryptographic hashes / MACs" in output
    assert "Encryption" in output
    assert "Compression" in output
    assert "msgpack" in output


@pytest.mark.parametrize(
    "flag, header",
    [
        ("--chunking", "Chunkers"),
        ("--hashing", "Cryptographic hashes / MACs"),
        ("--encrypting", "Encryption"),
        ("--compressing", "Compression"),
        ("--msgpacking", "msgpack"),
    ],
)
def test_benchmark_cpu_section_selection(archiver, monkeypatch, flag, header):
    # a flag runs that section and only that one
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    all_headers = ["Chunkers", "Cryptographic hashes / MACs", "Encryption", "Compression", "msgpack"]
    output = cmd(archiver, "benchmark", "cpu", flag)
    assert header in output
    for other in all_headers:
        if other != header:
            assert other not in output


def test_benchmark_cpu_json(archiver, monkeypatch):
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    output = cmd(archiver, "benchmark", "cpu", "--json")
    result = json.loads(output)
    assert isinstance(result, dict)
    # categories with "size" field (bytes)
    for category in ["chunkers", "hashes", "encryption"]:
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
    for category in ["msgpack"]:
        assert isinstance(result[category], list)
        assert len(result[category]) > 0
        for entry in result[category]:
            assert isinstance(entry["algo"], str)
            assert isinstance(entry["count"], int)
            assert isinstance(entry["time"], float)
    # compression also has the compressed size
    for entry in result["compression"]:
        assert isinstance(entry["size"], int)
        assert isinstance(entry["csize"], int)
        assert 0 < entry["csize"] <= entry["size"]


def test_benchmark_cpu_data_file(archiver, monkeypatch, tmp_path):
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    data_file = tmp_path / "data.txt"
    data_file.write_bytes(b"some quite compressible benchmark input data\n" * 10000)
    output = cmd(archiver, "benchmark", "cpu", "--compressing", "--data", str(data_file))
    assert "Compression" in output
    assert "MB/s" in output
    # the compression rows show the achieved compression ratio
    assert re.search(r"\d+\.\d\dx", output)


def test_benchmark_cpu_data_directory(archiver, monkeypatch, tmp_path):
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    data_dir = tmp_path / "corpus"
    (data_dir / "sub").mkdir(parents=True)
    (data_dir / "a.txt").write_bytes(b"first benchmark input file\n" * 5000)
    (data_dir / "sub" / "b.txt").write_bytes(b"second benchmark input file\n" * 5000)
    output = cmd(archiver, "benchmark", "cpu", "--compressing", "--data", str(data_dir))
    assert "Compression" in output
    assert re.search(r"\d+\.\d\dx", output)


def test_benchmark_cpu_data_json(archiver, monkeypatch, tmp_path):
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    data_file = tmp_path / "data.txt"
    data_file.write_bytes(b"some quite compressible benchmark input data\n" * 10000)
    output = cmd(archiver, "benchmark", "cpu", "--compressing", "--json", "--data", str(data_file))
    result = json.loads(output)
    for entry in result["compression"]:
        assert isinstance(entry["size"], int)
        assert isinstance(entry["csize"], int)
        assert 0 < entry["csize"] <= entry["size"]


def test_benchmark_cpu_data_missing(archiver, monkeypatch, tmp_path):
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    missing = str(tmp_path / "nonexistent")
    if archiver.FORK_DEFAULT:
        cmd(archiver, "benchmark", "cpu", "--compressing", "--data", missing, exit_code=CommandError().exit_code)
    else:
        with pytest.raises(CommandError, match="not a file or directory"):
            cmd(archiver, "benchmark", "cpu", "--compressing", "--data", missing)


def test_benchmark_cpu_data_empty(archiver, monkeypatch, tmp_path):
    monkeypatch.setenv("_BORG_BENCHMARK_CPU_TEST", "YES")
    data_file = tmp_path / "empty"
    data_file.write_bytes(b"")
    if archiver.FORK_DEFAULT:
        cmd(archiver, "benchmark", "cpu", "--compressing", "--data", str(data_file), exit_code=CommandError().exit_code)
    else:
        with pytest.raises(CommandError, match="no data found"):
            cmd(archiver, "benchmark", "cpu", "--compressing", "--data", str(data_file))
