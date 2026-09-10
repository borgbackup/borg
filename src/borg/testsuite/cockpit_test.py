"""Tests for the cockpit application. They need Textual; the borg process is faked, except in the slow test."""

import asyncio
import json
import subprocess
import time

import pytest

from borg.cockpit.events import (
    ArchiveProgress,
    FileStatus,
    LogMessage,
    ProcessFinished,
    ProgressMessage,
    ProgressPercent,
    Question,
    RawLine,
)
from borg.cockpit.session import LIST_LOGGER
from borg.platformflags import is_freebsd, is_win32

try:
    from borg.cockpit.app import BorgCockpitApp
    from borg.cockpit.prompt import PromptModal
    from borg.cockpit.screens import CreateScreen, ExtractScreen, GenericScreen, screen_for_command

    have_cockpit = True
except ImportError:
    have_cockpit = False

pytestmark = pytest.mark.skipif(not have_cockpit, reason="can not import BorgCockpitApp, is textual installed?")


class FakeRunner:
    """Replays events instead of running borg. After a prompt, it waits for the answer."""

    def __init__(self, args, callback, events=(), rc=0, json_stdout=False):
        self.args = list(args)
        self.callback = callback
        self.events = list(events)
        self.rc = rc
        self.json_stdout = json_stdout
        self.answers = []
        self.answered = asyncio.Event()

    async def start(self):
        for event in self.events:
            self.callback(event)
            if isinstance(event, Question) and event.needs_answer:
                await self.answered.wait()
                self.answered.clear()
            await asyncio.sleep(0)
        self.callback(ProcessFinished(rc=self.rc))

    async def answer(self, text):
        self.answers.append(text)
        self.answered.set()

    async def stop(self):
        pass


def make_runner_factory(events, rc=0):
    """A runner_factory for BorgCockpitApp, remembering the FakeRunner it created in the returned list."""
    created = []

    def factory(args, callback, **kwargs):
        runner = FakeRunner(args, callback, events=events, rc=rc, **kwargs)
        created.append(runner)
        return runner

    return factory, created


async def wait_until(pilot, predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timeout while waiting for the app"
        await pilot.pause(0.05)


async def run_to_the_end(app, inspect=None):
    """
    Run the app until the (fake) borg has finished and the widgets show the final state.

    Returns the texts shown by the status panel, the log text and the result of inspect(app), if given
    (the widgets can only be inspected while the app runs).
    """
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_until(pilot, lambda: not app.session.running)
        await pilot.pause(0.5)  # let the refresh timer show the final state
        check_layout(app)
        return app.query_one("#status").shown, log_text(app), inspect(app) if inspect else None


def log_text(app):
    return "\n".join(strip.text for strip in app.query_one("#standard-log-content").lines)


def check_layout(app):
    """The status panel must fit into the top row, next to the logo, with the log panel below."""
    top_row, status, log = app.query_one("#top-row"), app.query_one("#status"), app.query_one("#standard-log")
    assert top_row.size.height == status.HEIGHT  # size is the content area, without the border
    assert status.region.bottom <= top_row.region.bottom
    rc_line = app.query_one("#status-rc")
    assert rc_line.region.height == 1 and rc_line.region.bottom <= status.region.bottom
    assert log.region.y >= top_row.region.bottom and log.size.height >= 5


FINAL_JSON = {
    "archive": {
        "name": "test",
        "id": "0123abcd" * 8,
        "duration": 1.5,
        "stats": {
            "nfiles": 3,
            "original_size": 3000,
            "deduplicated_size": 300,
            "hashing_time": 0.1,
            "chunking_time": 0.2,
            "files_stats": {"A": 2, "M": 1, "d": 1},
            "store_stats": {"store_calls": 7},
        },
    },
    "repository": {"id": "ab" * 32, "location": "/repo"},
}


def test_screen_for_command():
    assert screen_for_command("create") is CreateScreen
    assert screen_for_command("import-tar") is CreateScreen
    assert screen_for_command("extract") is ExtractScreen
    assert screen_for_command("export-tar") is ExtractScreen
    assert screen_for_command("check") is GenericScreen
    assert screen_for_command(None) is GenericScreen


def test_app_create_screen():
    events = [
        LogMessage(message="Creating archive", levelname="INFO"),
        LogMessage(message="something is odd", levelname="WARNING"),
        ArchiveProgress(
            original_size=1000, deduplicated_size=100, nfiles=2, files_stats={"A": 1, "M": 1}, path="src/a"
        ),
        FileStatus(status="A", path="src/a"),
        FileStatus(status="M", path="src/b"),
        FileStatus(status="d", path="src"),
        ArchiveProgress(
            original_size=2900, deduplicated_size=290, nfiles=3, files_stats={"A": 2, "M": 1, "d": 1}, path="src/c"
        ),
        ArchiveProgress(finished=True),
    ]
    events += [RawLine(stream="stdout", line=line) for line in json.dumps(FINAL_JSON, indent=4).splitlines()]
    factory, runners = make_runner_factory(events, rc=1)
    app = BorgCockpitApp(borg_args=["create", "test", "src"], command="create", runner_factory=factory)
    shown, text, _ = asyncio.run(run_to_the_end(app))
    assert isinstance(app.main_screen, CreateScreen)
    assert runners[0].args == ["create", "test", "src"] and runners[0].json_stdout
    # the final numbers come from the --json output
    assert shown["status-files"] == "Files: 3"
    assert shown["status-original"] == "Original: 3.00 kB"
    assert shown["status-deduplicated"] == "Deduplicated: 300 B (10.0%)"
    assert shown["status-added"] == "Added: 2" and shown["status-modified"] == "Modified: 1"
    assert shown["status-other"] == "Other: 1" and shown["status-errors"] == "Errors: 0"
    assert shown["status-warnings"] == "Warnings: 1"
    assert shown["status-activity"].startswith("Archive: test (1.")
    assert shown["status-rc"] == "RC: 1"
    assert "Creating archive" in text and "something is odd" in text
    assert "A src/a" in text and "M src/b" in text and "d src" in text
    assert "Archive name: test" in text and "Number of files: 3" in text and "Store store calls: 7" in text


def test_app_extract_screen():
    events = [
        ProgressPercent(operation=1, msgid="extract", message="Calculating total archive size", current=0, total=0),
        ProgressPercent(operation=1, msgid="extract", message=" 25.0% Extracting: a", current=250, total=1000),
        LogMessage(message="+ a", name=LIST_LOGGER),
        LogMessage(message="- b", name=LIST_LOGGER),
        ProgressPercent(operation=1, msgid="extract", message=" 75.0% Extracting: c", current=750, total=1000),
        ProgressPercent(operation=1, msgid="extract", finished=True, message=""),
        ProgressPercent(operation=2, msgid="extract.permissions", message="Setting directory permissions 50%"),
    ]
    factory, runners = make_runner_factory(events)
    app = BorgCockpitApp(borg_args=["extract", "--list", "test"], command="extract", runner_factory=factory)
    shown, text, bar = asyncio.run(
        run_to_the_end(app, lambda app: (app.query_one("#extract-bar").total, app.query_one("#extract-bar").progress))
    )
    assert isinstance(app.main_screen, ExtractScreen)
    assert not runners[0].json_stdout
    assert bar == (1000, 1000)  # finished: complete
    assert shown["status-extracted"] == "Extracted: 1.00 kB / 1.00 kB"
    assert shown["status-items"] == "Items: 2"
    assert shown["status-included"] == "Included: 1" and shown["status-excluded"] == "Excluded: 1"
    assert shown["status-rc"] == "RC: 0"
    assert "+ a" in text and "- b" in text


def test_app_generic_screen():
    events = [
        ProgressPercent(operation=1, msgid="check.index", message="Checking index  50%", current=50, total=100),
        ProgressMessage(operation=2, msgid="cache.close", message="Saving files cache"),
        ProgressPercent(operation=1, msgid="check.index", finished=True, message=""),
        LogMessage(message="Archive consistency check complete, no problems found.", levelname="INFO"),
    ]
    factory, runners = make_runner_factory(events)
    app = BorgCockpitApp(borg_args=["check"], command="check", runner_factory=factory)
    shown, text, _ = asyncio.run(run_to_the_end(app))
    assert isinstance(app.main_screen, GenericScreen)
    assert shown["phases-title"] == "Phases"
    assert shown["phases"].splitlines() == [
        "[green]✔ ██████████ Checking index[/]",  # finished: without the last percentage
        "[bold white]▶ ░░░░░░░░░░ Saving files cache[/]",
    ]
    assert shown["status-warnings"] == "Warnings: 0" and shown["status-rc"] == "RC: 0"
    assert "no problems found" in text


def test_app_answers_prompt():
    events = [
        Question(kind="prompt", message="Do something dangerous? [yN]: ", msgid="BORG_TEST_PROMPT"),
        Question(kind="accepted_true", message="Doing it."),
    ]
    factory, runners = make_runner_factory(events)

    async def run():
        app = BorgCockpitApp(borg_args=["check", "--repair"], command="check", runner_factory=factory)
        async with app.run_test() as pilot:
            await wait_until(pilot, lambda: isinstance(app.screen, PromptModal))
            assert app.session.pending_question is not None

            # the dialog must be composed and laid out before it can be clicked
            def dialog_ready():
                buttons = app.screen.query("#prompt-yes")
                return bool(buttons) and buttons.first().region.width > 0

            await wait_until(pilot, dialog_ready)
            await pilot.pause(0.1)
            await pilot.click("#prompt-yes")
            await wait_until(pilot, lambda: not app.session.running)
            assert runners[0].answers == ["YES"]
            assert app.session.pending_question is None
            await pilot.pause(0.5)
            assert app.query_one("#status").shown["status-rc"] == "RC: 0"
            assert "Doing it." in log_text(app)

    asyncio.run(run())


def test_cockpit_app_create_archive(tmp_path):
    if not (is_freebsd or is_win32):
        pytest.skip("this slow test shall only run on FreeBSD and Windows")
    repo_path = tmp_path / "repo"
    input_path = tmp_path / "input"
    input_path.mkdir()
    for i in range(5000):
        (input_path / f"test{i}.txt").write_text(f"content {i}")

    subprocess.run(["borg", "-r", str(repo_path), "repo-create", "--encryption", "none-sha256"], check=True)

    async def run():
        app = BorgCockpitApp(
            borg_args=["-r", str(repo_path), "create", "--list", "test", str(input_path)], command="create"
        )

        async with app.run_test() as pilot:
            assert "BorgBackup" in app.TITLE
            assert app.is_running

            # Wait for process to finish
            while app.session.running:
                await pilot.pause(0.1)
            await pilot.pause(0.5)  # let the refresh timer show the final state

            assert app.session.rc == 0
            assert app.session.count("A") == 5000
            assert app.session.archive_name == "test"  # from the --json output
            assert app.query_one("#status").shown["status-rc"] == "RC: 0"

            await pilot.press("q")  # quit app

    asyncio.run(run())
