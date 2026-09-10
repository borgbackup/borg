"""
Borg Cockpit - UI Widgets.
"""

import random
import re
import time
from datetime import timedelta

from rich.markup import escape
from textual.app import ComposeResult
from textual.widgets import ProgressBar, RichLog, Static
from textual.containers import Vertical, Container
from ..helpers import classify_ec, format_file_size, format_timedelta
from ..helpers.parseformat import ellipsis_truncate
from .translator import T, TRANSLATOR


class StatusPanelBase(Static):
    """
    Base class of the panels showing the numbers of a borg run, next to the logo.

    Subclasses compose their lines (Static widgets with an id) and implement show_session(), which
    shows the state of a Session in them; HEIGHT is the number of lines they need, the screen sizes
    the top row accordingly. A line is only updated when its text changes.
    """

    HEIGHT = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = None
        self.shown = {}  # widget id -> text currently shown

    @staticmethod
    def _line(widget_id, label, value="", classes="status"):
        """A Static for one "Label: value" line, for compose()."""
        return Static(T(label) + value, classes=classes, id=widget_id)

    def show(self, widget_id, text):
        """Show <text> in the widget with <widget_id>, if it is not shown already."""
        if self.shown.get(widget_id) != text:
            self.shown[widget_id] = text
            self.query_one(f"#{widget_id}").update(text)

    def show_value(self, widget_id, label, value, truncate=False):
        """Show a translated label and a value; long values can be truncated to the panel width, so they don't wrap."""
        label = T(label)
        value = str(value)
        if truncate and value:
            space = (self.size.width or 60) - len(label) - 1
            value = ellipsis_truncate(value, space).rstrip()
        self.show(widget_id, label + escape(value))

    def update_from_session(self, session):
        """Show the current state of the session."""
        self.session = session
        self.show_session(session)

    def show_session(self, session):
        raise NotImplementedError

    def update_speed(self, session):
        """Called once per second, after Session.sample(): update the speed display, if the panel has one."""

    def show_speed(self, session):
        """Show the current rates, if the panel has a speed display."""

    def refresh_ui_labels(self):
        """Redo all lines with the current translation."""
        self.shown.clear()
        if self.session is not None:
            self.show_session(self.session)
            self.show_speed(self.session)

    # lines most panels have

    @staticmethod
    def _format_size(size):
        return "-" if size is None else format_file_size(size)

    def show_elapsed(self, session):
        if TRANSLATOR.enabled:
            # There seems to be no official formula for stardates, so we make something up.
            # When showing the stardate, it is an absolute time, not relative "elapsed time".
            ut = time.time()
            sd = (ut - 1735689600) / 60.0  # Minutes since 2025-01-01 00:00.00 UTC
            self.show("status-elapsed", f"Stardate {sd:.1f}")
        else:
            seconds = int(session.elapsed)
            days, seconds = divmod(seconds, 86400)
            h, m, s = seconds // 3600, (seconds % 3600) // 60, seconds % 60
            self.show("status-elapsed", f"Elapsed: {days:02d}d {h:02d}:{m:02d}:{s:02d}")

    def show_count(self, widget_id, label, count):
        """Show a count that is fine when zero and a warning otherwise."""
        widget = self.query_one(f"#{widget_id}")
        widget.set_class(count == 0, "errors-ok")
        widget.set_class(count != 0, "errors-warning")
        self.show_value(widget_id, label, count)

    def show_warnings(self, session):
        self.show_count("status-warnings", "Warnings: ", session.warnings + session.errors)

    def show_activity(self, session):
        """What borg works on right now."""
        self.show_value("status-activity", "Progress: ", session.progress_text, truncate=True)

    def show_rc(self, session):
        rc = session.rc
        if rc is None:
            self.show("status-rc", T("RC: ") + "RUNNING")
            return
        status = classify_ec(rc)
        widget = self.query_one("#status-rc")
        widget.set_class(status == "success", "rc-ok")
        widget.set_class(status == "warning", "rc-warning")
        widget.set_class(status not in ("success", "warning"), "rc-error")  # error, signal
        self.show("status-rc", T("RC: ") + str(rc))


class CreateStatusPanel(StatusPanelBase):
    """create, import-tar, recreate, transfer: the statistics of the archive being created."""

    HEIGHT = 17  # sparkline (4), speed (1), 12 lines

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.speed_history = [0.0] * SpeedSparkline.HISTORY_SIZE

    def compose(self) -> ComposeResult:
        with Vertical():
            yield SpeedSparkline(self.speed_history, id="speed-sparkline")
            yield self._line("status-speed", "Speed: ", "0 files/s", classes="")

            with Vertical(id="statuses"):
                yield self._line("status-elapsed", "Elapsed: ", "00d 00:00:00")
                yield self._line("status-files", "Files: ", "0")
                yield self._line("status-original", "Original: ", "-")
                yield self._line("status-deduplicated", "Deduplicated: ", "-")
                yield self._line("status-unchanged", "Unchanged: ", "0")
                yield self._line("status-modified", "Modified: ", "0")
                yield self._line("status-added", "Added: ", "0")
                yield self._line("status-other", "Other: ", "0")
                yield self._line("status-errors", "Errors: ", "0", classes="status errors-ok")
                yield self._line("status-warnings", "Warnings: ", "0", classes="status errors-ok")
                yield self._line("status-activity", "Progress: ")
                yield self._line("status-rc", "RC: ", "RUNNING")

    def show_session(self, session):
        self.show_elapsed(session)
        self.show_value("status-files", "Files: ", session.nfiles)
        original, deduplicated = session.original_size, session.deduplicated_size
        self.show_value("status-original", "Original: ", self._format_size(original))
        ratio = f" ({deduplicated * 100 / original:.1f}%)" if deduplicated is not None and original else ""
        self.show_value("status-deduplicated", "Deduplicated: ", self._format_size(deduplicated) + ratio)
        self.show_value("status-unchanged", "Unchanged: ", session.count("U-"))
        self.show_value("status-modified", "Modified: ", session.count("M"))
        self.show_value("status-added", "Added: ", session.count("A+"))
        self.show_value("status-other", "Other: ", sum(session.files_stats.values()) - session.count("U-MA+E"))
        self.show_count("status-errors", "Errors: ", session.count("E"))
        self.show_warnings(session)
        if not session.running and session.archive_name is not None:
            # the final --json output tells about the archive that was created.
            duration = session.archive_duration
            value = session.archive_name
            if duration is not None:
                value += f" ({format_timedelta(timedelta(seconds=duration))})"
            self.show_value("status-activity", "Archive: ", value, truncate=True)
        else:
            self.show_activity(session)
        self.show_rc(session)

    def update_speed(self, session):
        self.speed_history.append(session.files_per_second)
        self.speed_history = self.speed_history[-SpeedSparkline.HISTORY_SIZE :]
        self.query_one("#speed-sparkline").update_data(self.speed_history)
        self.show_speed(session)

    def show_speed(self, session):
        rates = f"{session.files_per_second:.0f} files/s, {format_file_size(session.original_bytes_per_second)}/s"
        self.show("status-speed", T("Speed: ") + rates)


class ExtractStatusPanel(StatusPanelBase):
    """extract, export-tar: a progress bar over the bytes to extract, and the counts of the --list lines."""

    HEIGHT = 14  # sparkline (4), speed (1), progress bar (1), 8 lines
    PHASE = "extract"  # the msgid of the progress operation the bar shows

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.speed_history = [0.0] * SpeedSparkline.HISTORY_SIZE

    def compose(self) -> ComposeResult:
        with Vertical():
            yield SpeedSparkline(self.speed_history, id="speed-sparkline")
            yield self._line("status-speed", "Speed: ", "0 B/s", classes="")
            yield ProgressBar(id="extract-bar")  # indeterminate until the total is known

            with Vertical(id="statuses"):
                yield self._line("status-extracted", "Extracted: ", "-")
                yield self._line("status-elapsed", "Elapsed: ", "00d 00:00:00")
                yield self._line("status-items", "Items: ", "0")
                yield self._line("status-included", "Included: ", "0")
                yield self._line("status-excluded", "Excluded: ", "0")
                yield self._line("status-warnings", "Warnings: ", "0", classes="status errors-ok")
                yield self._line("status-activity", "Progress: ")
                yield self._line("status-rc", "RC: ", "RUNNING")

    def show_session(self, session):
        phase = session.phase(self.PHASE)
        bar = self.query_one("#extract-bar")
        extracted = "-"
        if phase is not None and phase.total:
            current = phase.total if phase.finished else min(phase.current or 0, phase.total)
            bar.update(total=phase.total, progress=current)
            extracted = f"{format_file_size(current)} / {format_file_size(phase.total)}"
        elif phase is not None and phase.finished:  # there was nothing to extract
            bar.update(total=1, progress=1)
        self.show_value("status-extracted", "Extracted: ", extracted)
        self.show_elapsed(session)
        self.show_value("status-items", "Items: ", sum(session.status_counts.values()))
        self.show_value("status-included", "Included: ", session.status_counts.get("+", 0))
        self.show_value("status-excluded", "Excluded: ", session.status_counts.get("-", 0))
        self.show_warnings(session)
        self.show_activity(session)
        self.show_rc(session)

    def _rate(self, session):
        phase = session.phase(self.PHASE)
        return 0.0 if phase is None else phase.rate

    def update_speed(self, session):
        self.speed_history.append(self._rate(session))
        self.speed_history = self.speed_history[-SpeedSparkline.HISTORY_SIZE :]
        self.query_one("#speed-sparkline").update_data(self.speed_history)
        self.show_speed(session)

    def show_speed(self, session):
        self.show("status-speed", T("Speed: ") + f"{format_file_size(self._rate(session))}/s")


class GenericStatusPanel(StatusPanelBase):
    """All other commands: elapsed time, warnings, exit code and the phases borg reports progress for."""

    HEIGHT = 17  # 4 lines, the title, PHASE_LINES
    PHASE_LINES = 12  # the phases shown (the last ones, if there are more)
    BAR_WIDTH = 10
    PERCENTAGE = re.compile(r"\s*\d+(\.\d+)?%$")  # the percentage at the end of a progress message

    def compose(self) -> ComposeResult:
        with Vertical():
            with Vertical(id="statuses"):
                yield self._line("status-elapsed", "Elapsed: ", "00d 00:00:00")
                yield self._line("status-warnings", "Warnings: ", "0", classes="status errors-ok")
                yield self._line("status-archives", "Archives: ", "-")
                yield self._line("status-rc", "RC: ", "RUNNING")
            yield Static(T("Phases"), classes="panel-title", id="phases-title")
            yield Static("", id="phases")

    def show_session(self, session):
        self.show_elapsed(session)
        self.show_warnings(session)
        kept, pruned = session.archives_kept, session.archives_pruned
        self.show_value("status-archives", "Archives: ", f"{kept} kept, {pruned} pruned" if kept or pruned else "-")
        self.show_rc(session)
        self.show("phases-title", T("Phases"))
        space = (self.size.width or 60) - self.BAR_WIDTH - 3
        lines = []
        for phase in list(session.phases.values())[-self.PHASE_LINES :]:
            if phase.finished:
                mark, filled, style = "✔", self.BAR_WIDTH, "green"
            else:
                fraction = phase.fraction
                mark, filled, style = "▶", 0 if fraction is None else round(fraction * self.BAR_WIDTH), "bold white"
            bar = "█" * filled + "░" * (self.BAR_WIDTH - filled)
            message = phase.message or phase.msgid or ""
            if phase.finished:  # the last percentage borg reported before finishing is not the final one
                message = self.PERCENTAGE.sub("", message)
            text = ellipsis_truncate(message, space).rstrip()
            lines.append(f"[{style}]{mark} {bar} {escape(text)}[/]")
        self.show("phases", "\n".join(lines))


class StandardLog(Vertical):
    """The log panel: log messages, --list lines and everything else borg outputs."""

    # Styles for the --list status characters, see "Item flags" in the borg create help.
    STATUS_STYLES = {
        "E": "red",  # error
        "C": "yellow",  # regular file, changed while reading
        "?": "red",  # missing status, a bug
        "A": "white",  # added regular file (cache miss, slow!)
        "M": "white",  # modified regular file (cache hit, but different, slow!)
        "U": "green",  # unchanged regular file (cache hit)
        "-": "white",  # excluded
        "x": "white",  # skipped (dataless)
    }
    DEFAULT_STATUS_STYLE = "green"  # d, b, c, h, s, f, i: metadata only. +: included.
    # Styles for the log levels (and the prompts and the final statistics).
    LEVEL_STYLES = {
        "DEBUG": "dim",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold red",
        "PROMPT": "bold yellow",
        "STATS": "bold",
    }
    MAX_LINES = 5000  # lines kept for scrolling back

    def compose(self) -> ComposeResult:
        yield Static(T("Log"), classes="panel-title", id="standard-log-title")
        yield RichLog(
            id="standard-log-content", highlight=False, markup=True, auto_scroll=True, max_lines=self.MAX_LINES
        )

    def update_title(self):
        self.query_one("#standard-log-title").update(T("Log"))

    @classmethod
    def style_for(cls, line):
        """The rich style for a Line from the Session, None for plain text."""
        if line.kind == "status":
            return cls.STATUS_STYLES.get(line.tag, cls.DEFAULT_STATUS_STYLE)
        if line.kind == "archive":
            return "green" if line.tag == "kept" else "white"
        if line.kind == "log":
            return cls.LEVEL_STYLES.get(line.tag)
        if line.kind == "hint":
            return "bold yellow"
        return None

    def add_lines(self, lines, dropped=0):
        """Append the lines taken from Session.drain(); dropped lines are only mentioned."""
        if not lines and not dropped:
            return
        log_widget = self.query_one("#standard-log-content")
        if dropped:
            log_widget.write(f"[dim]... {dropped} more lines not shown ...[/]")
        for line in lines:
            text = escape(line.text)
            style = self.style_for(line)
            log_widget.write(f"[{style}]{text}[/]" if style else text)


class Starfield(Static):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Generate a unique seed for this instance to ensure random
        # distribution per session but stable appearance during resize.
        self._seed = random.randint(0, 1000000)  # nosec B311 - UI-only randomness, not for crypto

    def on_mount(self) -> None:
        self.call_after_refresh(self._update_art)

    def on_resize(self, event) -> None:
        self._update_art()

    def _update_art(self) -> None:
        """Render starfield."""
        w, h = self.size
        # Don't try to render if too small
        if w < 10 or h < 5:
            return

        # Use our instance seed to keep stars "static" (same pattern) during resize
        random.seed(self._seed)

        star_density = 0.1
        big_star_chance = 0.1

        from .theme import theme

        star_color = f"[{theme.variables['star-color']}]"
        star_bright_color = f"[{theme.variables['star-bright-color']}]"

        # 1. Create canvas (Starfield)
        canvas = [[(" ", "")] * w for _ in range(h)]
        for y in range(h):
            for x in range(w):
                if random.random() < star_density:  # nosec B311 - visual effect randomness
                    if random.random() < big_star_chance:  # nosec B311 - visual effect randomness
                        char = "*"
                        color = star_bright_color
                    else:
                        char = random.choice([".", "·"])  # nosec B311 - visual effect randomness
                        color = star_color
                    canvas[y][x] = (char, color)

        # 2. Render to string
        c_reset = "[/]"
        final_lines = []
        for row in canvas:
            line_str = ""
            for char, color in row:
                if char == " ":
                    line_str += " "
                else:
                    line_str += f"{color}{escape(char)}{c_reset}"
            final_lines.append(line_str)

        art_str = "\n".join(final_lines)
        self.update(art_str)


class Pulsar(Static):
    PULSAR_ART = "\n".join([" │ ", "─*─", " │ "])
    H = 3
    W = 3

    def on_mount(self) -> None:
        self.set_interval(4.0, self.pulse)
        self.update_art()

    def pulse(self) -> None:
        self.toggle_class("dim")

    def update_art(self) -> None:
        self.update(self.PULSAR_ART)


class Slogan(Static):
    SLOGAN = "**** You're welcome! ****"
    H = 1
    W = len(SLOGAN)

    def on_mount(self) -> None:
        self.update(self.SLOGAN)
        self.set_interval(1.0, self.pulse)

    def pulse(self) -> None:
        self.toggle_class("dim")

    def update_slogan(self):
        self.update(T(self.SLOGAN))


class Logo(Static):
    BORG_ART = [
        "██████╗  ██████╗ ██████╗  ██████╗ ",
        "██╔══██╗██╔═══██╗██╔══██╗██╔════╝ ",
        "██████╔╝██║   ██║██████╔╝██║  ███╗",
        "██╔══██╗██║   ██║██╔══██╗██║   ██║",
        "██████╔╝╚██████╔╝██║  ██║╚██████╔╝",
        "╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ",
    ]
    H = len(BORG_ART)
    W = max(len(line) for line in BORG_ART)

    def on_mount(self) -> None:
        from .theme import theme

        logo_color = theme.variables["logo-color"]

        lines = []
        for line in self.BORG_ART:
            lines.append(f"[bold {logo_color}]{escape(line)}[/]")
        self.update("\n".join(lines))


class LogoPanel(Container):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._seed = random.randint(0, 1000000)  # nosec B311 - UI-only randomness, not for crypto

    def compose(self) -> ComposeResult:
        yield Starfield()
        yield Logo(id="logo")
        yield Slogan(id="slogan")
        yield Pulsar()

    def on_resize(self, event) -> None:
        w, h = self.size
        # Needs enough space to position reasonably
        if w > 4 and h > 4:
            random.seed(self._seed)

            # Exclusion Zone Calculation
            # --------------------------

            # Logo top-left
            logo_y = (h - Logo.H) // 2 - 1
            logo_x = (w - Logo.W) // 2

            # Slogan top-left
            slogan_y = logo_y + Logo.H + 2
            slogan_x = (w - Slogan.W) // 2

            # Forbidden area
            # --------------
            # Combined rect over Logo and Slogan
            f_y1 = logo_y
            f_y2 = slogan_y + Slogan.H
            f_x1 = min(logo_x, slogan_x)
            f_x2 = max(logo_x + Logo.W, slogan_x + Slogan.W)

            # Update Logo and Slogan position
            # Note: In the overlay layer, widgets stack vertically.
            # Logo is at y=0 (height Logo.H).
            # Slogan is at y=Logo.H (height Slogan.H).
            # Pulsar is at y=Logo.H+Slogan.H (height Pulsar.H)
            # We must subtract these flow positions from the desired absolute positions.
            self.query_one(Logo).styles.offset = (logo_x, logo_y)
            self.query_one(Slogan).styles.offset = (slogan_x, slogan_y - Logo.H)

            # Pulsar: styles.offset moves the top-left corner.
            # So if offset is (px, py), it occupies x=[px, px+Pulsar.W), y=[py, py+Pulsar.H).

            # Find a valid Pulsar position
            for _ in range(20):
                # Random position
                max_x = max(0, w - Pulsar.W)
                max_y = max(0, h - Pulsar.H)

                px = random.randint(0, max_x)  # nosec B311 - visual placement randomness
                py = random.randint(0, max_y)  # nosec B311 - visual placement randomness

                # Pulsar Rect:
                p_x1, p_y1 = px, py
                p_x2, p_y2 = px + Pulsar.W, py + Pulsar.H

                # Check intersection with forbidden rect
                overlap_x = (p_x1 < f_x2) and (p_x2 > f_x1)
                overlap_y = (p_y1 < f_y2) and (p_y2 > f_y1)

                if overlap_x and overlap_y:
                    continue  # Try again

                # No overlap!
                offset_x, offset_y = px, py - (Logo.H + Slogan.H)
                break
            else:
                # Fallback if no safe spot found (e.g. screen too small):
                # Place top-left or keep last valid. random 0,0 is safe-ish.
                offset_x, offset_y = 0, 0 - (Logo.H + Slogan.H)
            self.query_one(Pulsar).styles.offset = (offset_x, offset_y)


class SpeedSparkline(Static):
    """
    Custom 4-line height sparkline.
    """

    HISTORY_SIZE = 99
    BLOCKS = [".", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]

    def __init__(self, data: list[float] = None, **kwargs):
        super().__init__(**kwargs)
        self._data = data or []

    def update_data(self, data: list[float]):
        self._data = data
        self.refresh_chart()

    def refresh_chart(self):
        if not self._data:
            self.update("")
            return

        width = self.size.width or self.HISTORY_SIZE
        # Slice data to width
        dataset = self._data[-width:]
        if not dataset:
            self.update("")
            return

        max_val = max(dataset) if dataset else 1.0
        max_val = max(max_val, 1.0)  # Avoid div by zero

        # We have 4 lines, each can take 8 levels. Total 32 levels.
        # Normalize each data point to 0..32

        lines = [[], [], [], []]

        for val in dataset:
            # Scale to 0-32
            scaled = (val / max_val) * 32

            # Generate 4 stacked chars
            for i in range(4):
                # i=0 is top line, i=3 is bottom line
                # Thresholds: Top(24), Mid-High(16), Mid-Low(8), Low(0)
                threshold = (3 - i) * 8
                level = int(scaled - threshold)
                level = max(0, min(8, level))
                lines[i].append(self.BLOCKS[level])

        # Join lines
        rows = ["".join(line) for line in lines]
        self.update("\n".join(rows))

    def on_resize(self, event):
        self.refresh_chart()
