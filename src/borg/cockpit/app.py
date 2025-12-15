"""
Borg Cockpit - Application Entry Point.
"""

import asyncio
import time

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer
from textual.containers import Horizontal, Container

from .theme import theme


class BorgCockpitApp(App):
    """The main TUI Application class for Borg Cockpit."""

    from .. import __version__ as BORG_VERSION

    TITLE = f"Cockpit for BorgBackup {BORG_VERSION}"
    CSS_PATH = "cockpit.tcss"
    BINDINGS = [("q", "quit", "Quit"), ("ctrl+c", "quit", "Quit"), ("t", "toggle_translator", "Toggle Translator")]

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        from .widgets import LogoPanel, StatusPanel, StandardLog

        yield Header(show_clock=True)

        with Container(id="main-grid"):
            with Horizontal(id="top-row"):
                yield LogoPanel(id="logopanel")
                yield StatusPanel(id="status")

            yield StandardLog(id="standard-log")

        yield Footer()

    def get_theme_variable_defaults(self):
        # make these variables available to ALL themes
        return {
            "pulsar-color": "#ffffff",
            "pulsar-dim-color": "#000000",
            "star-color": "#888888",
            "star-bright-color": "#ffffff",
            "logo-color": "#00dd00",
        }

    def on_load(self) -> None:
        """Initialize theme before UI."""
        self.register_theme(theme)
        self.theme = theme.name

    def on_mount(self) -> None:
        """Initialize components."""
        from .runner import BorgRunner

        self.query_one("#logo").styles.animate("opacity", 1, duration=1)
        self.query_one("#slogan").styles.animate("opacity", 1, duration=1)

        self.start_time = time.monotonic()
        self.process_running = True
        args = getattr(self, "borg_args", ["--version"])  # Default to safe command if none passed
        self.runner = BorgRunner(args, self.handle_log_event)
        self.runner_task = asyncio.create_task(self.runner.start())

        # Speed tracking
        self.total_lines_processed = 0
        self.last_lines_processed = 0
        self.speed_timer = self.set_interval(1.0, self.compute_speed)

    def compute_speed(self) -> None:
        """Calculate and update speed (lines per second)."""
        current_lines = self.total_lines_processed
        lines_per_second = float(current_lines - self.last_lines_processed)
        self.last_lines_processed = current_lines

        status_panel = self.query_one("#status")
        status_panel.update_speed(lines_per_second / 1000)
        if self.process_running:
            status_panel.elapsed_time = time.monotonic() - self.start_time

    async def on_unmount(self) -> None:
        """Cleanup resources on app shutdown."""
        if hasattr(self, "runner"):
            await self.runner.stop()

    async def action_quit(self) -> None:
        """Handle quit action."""
        if hasattr(self, "speed_timer"):
            self.speed_timer.stop()
        if hasattr(self, "runner"):
            await self.runner.stop()
        if hasattr(self, "runner_task"):
            await self.runner_task
        self.query_one("#logo").styles.animate("opacity", 0, duration=2)
        self.query_one("#slogan").styles.animate("opacity", 0, duration=2)
        await asyncio.sleep(2)  # give the user a chance the see the borg RC
        self.exit()

    def action_toggle_translator(self) -> None:
        """Toggle the universal translator."""
        from .translator import TRANSLATOR

        TRANSLATOR.toggle()
        # Refresh dynamic UI elements
        self.query_one("#status").refresh_ui_labels()
        self.query_one("#standard-log").update_title()
        self.query_one("#slogan").update_slogan()

    def handle_log_event(self, data: dict):
        """Process a event from BorgRunner."""
        msg_type = data.get("type", "log")

        if msg_type == "stream_line":
            self.total_lines_processed += 1
            line = data.get("line", "")
            widget = self.query_one("#standard-log")
            widget.add_line(line)

        elif msg_type == "process_finished":
            self.process_running = False
            rc = data.get("rc", 0)
            self.query_one("#status").rc = rc
