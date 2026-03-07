import asyncio
import subprocess

import pytest

from borg.platformflags import is_freebsd, is_win32

try:
    from borg.cockpit.app import BorgCockpitApp

    have_cockpit = True
except ImportError:
    have_cockpit = False

pytestmark = pytest.mark.skipif(not have_cockpit, reason="can not import BorgCockpitApp, is textual installed?")


def test_cockpit_app_create_archive(tmp_path):
    if not (is_freebsd or is_win32):
        pytest.skip("this slow test shall only run on FreeBSD and Windows")
    repo_path = tmp_path / "repo"
    input_path = tmp_path / "input"
    input_path.mkdir()
    for i in range(5000):
        (input_path / f"test{i}.txt").write_text(f"content {i}")

    subprocess.run(["borg", "-r", str(repo_path), "repo-create", "--encryption", "none"], check=True)

    async def run():
        app = BorgCockpitApp()
        app.borg_args = ["-r", str(repo_path), "create", "--list", "test", str(input_path)]

        async with app.run_test() as pilot:
            assert "BorgBackup" in app.TITLE
            assert app.is_running

            # Wait for process to finish
            while getattr(app, "process_running", True):
                await pilot.pause(0.1)

            status_panel = pilot.app.query_one("#status")
            assert status_panel.rc == 0

            assert app.total_lines_processed > 0

            await pilot.press("q")  # quit app

    asyncio.run(run())
