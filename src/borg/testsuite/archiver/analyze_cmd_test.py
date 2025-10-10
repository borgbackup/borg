import pathlib

from ...constants import *  # NOQA
from . import cmd, generate_archiver_tests, RK_ENCRYPTION

pytest_generate_tests = lambda metafunc: generate_archiver_tests(metafunc, kinds="local")  # NOQA


def test_analyze(archivers, request):
    def create_archive():
        cmd(archiver, "create", "archive", archiver.input_path)

    def analyze_archives():
        return cmd(archiver, "analyze", "-a", "archive")

    archiver = request.getfixturevalue(archivers)

    cmd(archiver, "repo-create", RK_ENCRYPTION)
    input_path = pathlib.Path(archiver.input_path)

    # 1st archive
    (input_path / "file1").write_text("1")
    create_archive()

    # 2nd archive
    (input_path / "file2").write_text("22")
    create_archive()

    assert "/input: 2" in analyze_archives()  # 2nd archive added 1 chunk for input path

    # 3rd archive
    (input_path / "file3").write_text("333")
    create_archive()

    assert "/input: 5" in analyze_archives()  # 2nd/3rd archives added 2 chunks for input path

    # 4th archive
    (input_path / "file2").unlink()
    create_archive()

    assert "/input: 7" in analyze_archives()  # 2nd/3rd archives added 2, 4th archive removed 1
