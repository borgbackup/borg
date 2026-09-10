"""
Borg Cockpit - the screens, one per kind of borg command.

All screens have the same layout: the header, the logo panel next to a status panel (the part that
depends on the command), the log panel and the footer.
"""

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Footer, Header

from .widgets import CreateStatusPanel, ExtractStatusPanel, GenericStatusPanel, LogoPanel, StandardLog


class CockpitScreen(Screen):
    """The common layout; PANEL is the status panel class of the screen."""

    PANEL = GenericStatusPanel

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="main-grid"):
            with Horizontal(id="top-row"):
                yield LogoPanel(id="logopanel")
                yield self.PANEL(id="status")

            yield StandardLog(id="standard-log")

        yield Footer()

    def on_mount(self) -> None:
        # the top row is as high as the status panel needs, plus the border of the row.
        self.query_one("#top-row").styles.height = self.PANEL.HEIGHT + 2
        self.query_one("#logo").styles.animate("opacity", 1, duration=1)
        self.query_one("#slogan").styles.animate("opacity", 1, duration=1)

    def refresh_from_session(self, session) -> None:
        """Show the current state of the session."""
        self.query_one("#status").update_from_session(session)
        lines, dropped = session.drain()
        self.query_one("#standard-log").add_lines(lines, dropped)

    def sample_speed(self, session) -> None:
        """Called once per second, after Session.sample(): update the speed display."""
        self.query_one("#status").update_speed(session)

    def refresh_ui_labels(self) -> None:
        """Redo the labels with the current translation."""
        self.query_one("#status").refresh_ui_labels()
        self.query_one("#standard-log").update_title()
        self.query_one("#slogan").update_slogan()

    def fade_out(self) -> None:
        """Fade the logo out, for the exit."""
        self.query_one("#logo").styles.animate("opacity", 0, duration=2)
        self.query_one("#slogan").styles.animate("opacity", 0, duration=2)


class CreateScreen(CockpitScreen):
    """create, import-tar, recreate, transfer: the statistics of the archive being created."""

    PANEL = CreateStatusPanel


class ExtractScreen(CockpitScreen):
    """extract, export-tar: a progress bar over the bytes to extract."""

    PANEL = ExtractStatusPanel


class GenericScreen(CockpitScreen):
    """All other commands: the phases borg reports progress for."""

    PANEL = GenericStatusPanel


SCREENS = {
    "create": CreateScreen,
    "import-tar": CreateScreen,
    "recreate": CreateScreen,
    "transfer": CreateScreen,
    "extract": ExtractScreen,
    "export-tar": ExtractScreen,
}


def screen_for_command(command):
    """The screen class for a borg subcommand (None: unknown command)."""
    return SCREENS.get(command, GenericScreen)
