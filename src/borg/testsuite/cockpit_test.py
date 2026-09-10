"""Tests for the cockpit application. They need Textual; the borg process is faked, except in the slow test."""

import asyncio
import subprocess
import time

import pytest

from borg.cockpit.events import ArchiveProgress, FileStatus, LogMessage, ProcessFinished, Question
from borg.platformflags import is_freebsd, is_win32

try:
    from borg.cockpit.app import BorgCockpitApp
    from borg.cockpit.prompt import PromptModal

    have_cockpit = True
except ImportError:
    have_cockpit = False

pytestmark = pytest.mark.skipif(not have_cockpit, reason="can not import BorgCockpitApp, is textual installed?")


class FakeRunner:
    """Replays events instead of running borg. After a prompt, it waits for the answer."""

    def __init__(self, args, callback, events=(), rc=0):
        self.args = list(args)
        self.callback = callback
        self.events = list(events)
        self.rc = rc
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

    def factory(args, callback):
        runner = FakeRunner(args, callback, events=events, rc=rc)
        created.append(runner)
        return runner

    return factory, created


async def wait_until(pilot, predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timeout while waiting for the app"
        await pilot.pause(0.05)


def log_text(app):
    return "\n".join(strip.text for strip in app.query_one("#standard-log-content").lines)


def test_app_shows_create_progress():
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
            original_size=3000, deduplicated_size=300, nfiles=3, files_stats={"A": 2, "M": 1, "d": 1}, path="src/c"
        ),
        ArchiveProgress(finished=True),
    ]
    factory, runners = make_runner_factory(events, rc=1)

    async def run():
        app = BorgCockpitApp(borg_args=["create", "test", "src"], runner_factory=factory)
        async with app.run_test() as pilot:
            await wait_until(pilot, lambda: not app.session.running)
            await pilot.pause(0.5)  # let the refresh timer show the final state
            status = app.query_one("#status")
            # the counts come from the 3 --list lines (A, M, d), the sizes from archive_progress
            assert status.files_count == 3
            assert (status.added_count, status.modified_count, status.other_count, status.error_count) == (1, 1, 1, 0)
            assert (status.original_size, status.deduplicated_size) == (3000, 300)
            assert status.rc == 1
            assert status.progress_text == ""
            text = log_text(app)
            assert "Creating archive" in text and "something is odd" in text
            assert "A src/a" in text and "M src/b" in text and "d src" in text

    asyncio.run(run())
    assert runners[0].args == ["create", "test", "src"]


def test_app_answers_prompt():
    events = [
        Question(kind="prompt", message="Do something dangerous? [yN]: ", msgid="BORG_TEST_PROMPT"),
        Question(kind="accepted_true", message="Doing it."),
    ]
    factory, runners = make_runner_factory(events)

    async def run():
        app = BorgCockpitApp(borg_args=["check", "--repair"], runner_factory=factory)
        async with app.run_test() as pilot:
            await wait_until(pilot, lambda: isinstance(app.screen, PromptModal))
            assert app.session.pending_question is not None
            await pilot.click("#prompt-yes")
            await wait_until(pilot, lambda: not app.session.running)
            assert runners[0].answers == ["YES"]
            assert app.session.pending_question is None
            await pilot.pause(0.5)
            assert app.query_one("#status").rc == 0
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
        app = BorgCockpitApp(borg_args=["-r", str(repo_path), "create", "--list", "test", str(input_path)])

        async with app.run_test() as pilot:
            assert "BorgBackup" in app.TITLE
            assert app.is_running

            # Wait for process to finish
            while app.session.running:
                await pilot.pause(0.1)
            await pilot.pause(0.5)  # let the refresh timer show the final state

            assert app.session.rc == 0
            assert app.session.count("A") == 5000  # from the --list lines
            assert app.query_one("#status").rc == 0

            await pilot.press("q")  # quit app

    asyncio.run(run())
