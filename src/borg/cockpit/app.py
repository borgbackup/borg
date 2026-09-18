"""
Borg Cockpit - Application Entry Point.
"""

import asyncio
import signal

from textual.app import App
from textual.css.query import NoMatches

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
    # These commands output the statistics of the new archive as JSON on stdout when given --json.
    FINAL_STATS_COMMANDS = ("create", "import-tar")
    # The signals asking the cockpit to end, see handle_signals().
    SIGNALS = ("SIGTERM", "SIGHUP", "SIGINT")

    def __init__(self, borg_args=None, command=None, runner_factory=None, **kwargs):
        """
        :param borg_args: the borg command line to run, without --cockpit [borg --version].
        :param command: the borg subcommand in borg_args, e.g. "create"; it selects the screen [None: generic].
        :param runner_factory: callable(args, callback, json_stdout=...) giving a BorgRunner-like object, for tests.
        """
        super().__init__(**kwargs)
        self.borg_args = ["--version"] if borg_args is None else list(borg_args)
        self.command = command
        self.json_stdout = command in self.FINAL_STATS_COMMANDS
        self.runner_factory = runner_factory
        self.session = Session(command=command, capture_stdout=self.json_stdout)
        self.main_screen = None
        self.runner = None
        self.runner_task = None
        self.handled_signals = []  # the names of the signals handled by on_signal()
        self.terminate_task = None

    def get_default_screen(self):
        """The screen for the command that runs (Textual calls this when the app starts)."""
        from .screens import screen_for_command

        self.main_screen = screen_for_command(self.command)()
        return self.main_screen

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
        # Delay runner start until after widgets are fully mounted
        self.call_after_refresh(self.start_runner)

    def start_runner(self) -> None:
        """Start the Borg runner after all widgets are mounted."""
        from .runner import BorgRunner

        factory = self.runner_factory or BorgRunner
        self.runner = factory(self.borg_args, self.handle_event, json_stdout=self.json_stdout)
        self.runner_task = asyncio.create_task(self.runner.start())
        self.speed_timer = self.set_interval(self.SPEED_INTERVAL, self.sample_speed)
        self.refresh_timer = self.set_interval(self.REFRESH_INTERVAL, self.refresh_from_session)
        self.handle_signals()

    def handle_signals(self) -> None:
        """
        End in an orderly way when a signal asks the cockpit to end (e.g. the terminal window gets closed).

        borg's main() has installed handlers raising an exception for these signals. Raised at some random
        place inside the event loop, it would end the app with a traceback, without waiting for borg.
        The event loop's signal handlers replace them while the app runs.
        """
        loop = asyncio.get_running_loop()
        for name in self.SIGNALS:
            signum = getattr(signal, name, None)
            if signum is None:
                continue  # no such signal on this platform
            try:
                loop.add_signal_handler(signum, self.on_signal, name)
            except (NotImplementedError, ValueError, RuntimeError):
                continue  # not supported by this event loop (Windows) or not running in the main thread
            self.handled_signals.append(name)

    def on_signal(self, name) -> None:
        """Got a signal: terminate borg, wait for it and exit; main() then exits with borg's exit code."""
        if self.terminate_task is None:
            self.terminate_task = asyncio.create_task(self.terminate())

    async def terminate(self) -> None:
        await self.stop_borg()
        self.exit()

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
        """Compute the current rates and show them."""
        self.session.sample()
        try:
            self.main_screen.sample_speed(self.session)
        except NoMatches:
            pass  # the widgets are being torn down (the app exits), the timer still fires

    def refresh_from_session(self) -> None:
        """Show the current state of the session in the widgets."""
        try:
            self.main_screen.refresh_from_session(self.session)
        except NoMatches:
            pass  # see sample_speed()

    async def on_unmount(self) -> None:
        """Cleanup resources on app shutdown."""
        if self.runner is not None:
            await self.runner.stop()

    async def stop_borg(self) -> None:
        """Terminate borg if it still runs, and wait until it has exited."""
        if self.runner is not None:
            await self.runner.stop()
        if self.runner_task is not None:
            await self.runner_task

    async def action_quit(self) -> None:
        """Handle quit action."""
        if hasattr(self, "speed_timer"):
            self.speed_timer.stop()
        await self.stop_borg()
        self.main_screen.fade_out()
        await asyncio.sleep(2)  # give the user a chance the see the borg RC
        self.exit()

    def action_toggle_translator(self) -> None:
        """Toggle the universal translator."""
        from .translator import TRANSLATOR

        TRANSLATOR.toggle()
        self.main_screen.refresh_ui_labels()
