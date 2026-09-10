"""
Borg Runner - runs borg as a subprocess and turns its output into events.
"""

import asyncio
import logging
import os
import sys

from ..platformflags import is_win32
from .events import ProcessFinished, RawLine, parse_json_line

# The options the cockpit needs for machine-readable output. They are common options, so they are
# valid in front of the subcommand; borg merges them with the options the user gave at any level.
INJECTED_OPTIONS = ("--log-json", "--progress")


def borg_command(args, executable=None, json_stdout=False):
    """
    Build the command line to run borg with the given args and the cockpit's options injected.

    :param args: the borg command line (without the borg executable and without --cockpit).
    :param executable: the command prefix starting borg [the interpreter / pyinstaller binary running this code].
    :param json_stdout: also add --json, so the command outputs its final results as JSON on stdout.
    """
    if executable is None:
        if getattr(sys, "frozen", False):
            executable = [sys.executable]  # sys.executable is the pyinstaller-made binary
        else:
            executable = [sys.executable, "-m", "borg"]
    args = list(args)
    if json_stdout and "--json" not in args:
        # --json is an option of the subcommand, so it must come after it: at the end of the command line,
        # or before a "--" end-of-options marker (as used by e.g. --paths-from-command).
        args.insert(args.index("--") if "--" in args else len(args), "--json")
    injected = [option for option in INJECTED_OPTIONS if option not in args]
    return list(executable) + injected + args


class BorgRunner:
    """
    Runs borg as a subprocess, parses its output into events and hands them to a callback, one at a time.

    stderr carries the --log-json stream, one JSON object per line, see docs/internals/frontends.rst.
    Everything else (stdout lines, stderr lines that are not JSON) is passed on as RawLine events.
    stdin is a pipe, so that the application can answer borg's yes/no prompts via answer().

    On POSIX, borg runs in a new session and thus has no controlling terminal: nothing it does can
    mess with the terminal the TUI runs on. A passphrase prompt then falls back to stderr/stdin, where
    the cockpit sees it (see Session), instead of being painted over the TUI.
    """

    READ_SIZE = 64 * 1024
    # An unterminated line (e.g. a prompt waiting for input) is passed on after this idle time [seconds].
    PARTIAL_LINE_TIMEOUT = 1.0
    # How long to wait for borg to finish after SIGTERM before killing it [seconds].
    TERMINATE_TIMEOUT = 10.0

    def __init__(self, args, callback, *, executable=None, json_stdout=False):
        """
        :param args: the borg command line (without the borg executable and without --cockpit).
        :param callback: called with each Event, the last one being ProcessFinished.
        :param executable: see borg_command(), for tests.
        :param json_stdout: see borg_command().
        """
        self.args = list(args)
        self.callback = callback
        self.executable = executable
        self.json_stdout = json_stdout
        self.process = None
        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Run borg to completion, handing all events to the callback."""
        if self.process is not None:
            self.logger.warning("Borg process already running.")
            return
        cmd = borg_command(self.args, self.executable, self.json_stdout)
        self.logger.info(f"Starting Borg process: {cmd}")
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        kwargs = {} if is_win32 else {"start_new_session": True}
        try:
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                **kwargs,
            )
            await asyncio.gather(self._read(self.process.stdout, "stdout"), self._read(self.process.stderr, "stderr"))
            rc = await self.process.wait()
            self.callback(ProcessFinished(rc=rc))
        except Exception as e:
            self.logger.error(f"Failed to run Borg process: {e}")
            self.callback(ProcessFinished(rc=-1, error=str(e)))
        finally:
            self.process = None

    async def _read(self, stream, name):
        """Pass on the lines of <stream>; an unterminated line is passed on as partial after some idle time."""
        buffer = b""
        while True:
            try:
                data = await asyncio.wait_for(stream.read(self.READ_SIZE), self.PARTIAL_LINE_TIMEOUT)
            except TimeoutError:
                if buffer:
                    self._line(name, buffer, partial=True)
                    buffer = b""
                continue
            if not data:  # EOF
                if buffer:
                    self._line(name, buffer)
                return
            *lines, buffer = (buffer + data).split(b"\n")
            for line in lines:
                self._line(name, line)

    def _line(self, stream, raw, partial=False):
        line = raw.decode("utf-8", errors="replace").rstrip("\r")
        if not line.strip():
            return
        event = parse_json_line(line) if stream == "stderr" and not partial else None
        self.callback(event if event is not None else RawLine(stream=stream, line=line, partial=partial))

    async def answer(self, text):
        """Send the answer to a prompt to borg's stdin."""
        process = self.process
        if process is None or process.stdin is None:
            return
        try:
            process.stdin.write((text + "\n").encode("utf-8"))
            await process.stdin.drain()
        except (OSError, ValueError) as e:  # borg is gone or its stdin is closed
            self.logger.warning(f"Could not send the answer to borg: {e}")

    async def stop(self):
        """Terminate borg if it is still running; borg handles SIGTERM by finishing in an orderly way."""
        process = self.process
        if process is not None and process.returncode is None:
            self.logger.info("Terminating Borg process...")
            try:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), self.TERMINATE_TIMEOUT)
                except TimeoutError:
                    process.kill()
                    await process.wait()
            except ProcessLookupError:
                pass  # already dead
