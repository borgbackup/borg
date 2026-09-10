"""
Borg Cockpit - Application Entry Point.
"""

import asyncio

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer
from textual.containers import Horizontal, Container

from .events import Question
from .session import Session
from .theme import theme


class BorgCockpitApp(App):
    """The main TUI Application class for Borg Cockpit."""

    from .. import __version__ as BORG_VERSION

    TITLE = f"Cockpit for BorgBackup {BORG_VERSION}"
    CSS_PATH = "cockpit.tcss"
    BINDINGS = [("q", "quit", "Quit"), ("ctrl+c", "quit", "Quit"), ("t", "toggle_translator", "Toggle Translator")]

    SPEED_INTERVAL = 1.0  # seconds between two speed samples (one sparkline column each)
    REFRESH_INTERVAL = 0.2  # seconds between two refreshes of the widgets from the session

    def __init__(self, borg_args=None, runner_factory=None, **kwargs):
        """
        :param borg_args: the borg command line to run, without --cockpit [borg --version].
        :param runner_factory: callable(args, callback) giving a BorgRunner-like object, for tests [BorgRunner].
        """
        super().__init__(**kwargs)
        self.borg_args = ["--version"] if borg_args is None else list(borg_args)
        self.runner_factory = runner_factory
        self.session = Session()
        self.runner = None
        self.runner_task = None

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
        self.query_one("#logo").styles.animate("opacity", 1, duration=1)
        self.query_one("#slogan").styles.animate("opacity", 1, duration=1)

        # Delay runner start until after widgets are fully mounted
        self.call_after_refresh(self.start_runner)

    def start_runner(self) -> None:
        """Start the Borg runner after all widgets are mounted."""
        from .runner import BorgRunner

        factory = self.runner_factory or BorgRunner
        self.runner = factory(self.borg_args, self.handle_event)
        self.runner_task = asyncio.create_task(self.runner.start())
        self.speed_timer = self.set_interval(self.SPEED_INTERVAL, self.sample_speed)
        self.refresh_timer = self.set_interval(self.REFRESH_INTERVAL, self.refresh_from_session)

    @property
    def process_running(self):
        return self.session.running

    def handle_event(self, event) -> None:
        """Process an event from the runner: the session does the bookkeeping, a prompt needs a dialog."""
        self.session.feed(event)
        if isinstance(event, Question) and event.needs_answer:
            from .prompt import PromptModal

            self.push_screen(PromptModal(event.message), callback=self.send_answer)

    def send_answer(self, answer) -> None:
        """Send the answer given in the prompt dialog to borg."""
        if answer is not None and self.runner is not None:
            self.run_worker(self.runner.answer(answer))

    def sample_speed(self) -> None:
        """Compute the current rates and add a column to the speed sparkline."""
        self.session.sample()
        self.query_one("#status").update_speed(self.session.files_per_second)

    def refresh_from_session(self) -> None:
        """Show the current state of the session in the widgets."""
        self.query_one("#status").update_from_session(self.session)
        lines, dropped = self.session.drain()
        self.query_one("#standard-log").add_lines(lines, dropped)

    async def on_unmount(self) -> None:
        """Cleanup resources on app shutdown."""
        if self.runner is not None:
            await self.runner.stop()

    async def action_quit(self) -> None:
        """Handle quit action."""
        if hasattr(self, "speed_timer"):
            self.speed_timer.stop()
        if self.runner is not None:
            await self.runner.stop()
        if self.runner_task is not None:
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
