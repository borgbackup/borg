"""
Borg Runner - Manages Borg subprocess execution and output parsing.
"""

import asyncio
import logging
import os
import sys
from typing import Optional, Callable, List


class BorgRunner:
    """
    Manages the execution of the borg subprocess and parses its JSON output.
    """

    def __init__(self, command: List[str], log_callback: Callable[[dict], None]):
        self.command = command
        self.log_callback = log_callback
        self.process: Optional[asyncio.subprocess.Process] = None
        self.logger = logging.getLogger(__name__)

    async def start(self):
        """
        Starts the Borg subprocess and processes its output.
        """
        if self.process is not None:
            self.logger.warning("Borg process already running.")
            return

        if getattr(sys, "frozen", False):
            cmd = [sys.executable] + self.command  # executable == pyinstaller binary
        else:
            cmd = [sys.executable, "-m", "borg"] + self.command  # executable == python interpreter

        self.logger.info(f"Starting Borg process: {cmd}")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self.process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env
            )

            async def read_stream(stream, stream_name):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded_line = line.decode("utf-8", errors="replace").rstrip()
                    if decoded_line:
                        self.log_callback({"type": "stream_line", "stream": stream_name, "line": decoded_line})

            # Read both streams concurrently
            await asyncio.gather(read_stream(self.process.stdout, "stdout"), read_stream(self.process.stderr, "stderr"))

            rc = await self.process.wait()
            self.log_callback({"type": "process_finished", "rc": rc})

        except Exception as e:
            self.logger.error(f"Failed to run Borg process: {e}")
            self.log_callback({"type": "process_finished", "rc": -1, "error": str(e)})
        finally:
            self.process = None

    async def stop(self):
        """
        Stops the Borg subprocess if it is running.
        """
        if self.process and self.process.returncode is None:
            self.logger.info("Terminating Borg process...")
            try:
                self.process.terminate()
                await self.process.wait()
            except ProcessLookupError:
                pass  # Process already dead
