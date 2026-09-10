"""
Borg Cockpit - UI Widgets.
"""

import random
import time

from rich.markup import escape
from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widgets import Static, RichLog
from textual.containers import Vertical, Container
from ..helpers import classify_ec, format_file_size
from ..helpers.parseformat import ellipsis_truncate
from .translator import T, TRANSLATOR


class StatusPanel(Static):
    """The numbers of the current borg run, shown from the Session, see update_from_session()."""

    elapsed_time = reactive(0.0, init=False)
    files_count = reactive(0, init=False)  # regular files processed, or all listed items without archive_progress
    original_size = reactive(None, init=False)  # bytes, None: unknown (no archive_progress seen)
    deduplicated_size = reactive(None, init=False)
    unchanged_count = reactive(0, init=False)
    modified_count = reactive(0, init=False)
    added_count = reactive(0, init=False)
    other_count = reactive(0, init=False)
    error_count = reactive(0, init=False)
    progress_text = reactive("", init=False)  # what borg works on right now
    rc = reactive(None, init=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.speed_history = [0.0] * SpeedSparkline.HISTORY_SIZE
        self.files_per_second = 0.0

    def compose(self) -> ComposeResult:
        with Vertical():
            yield SpeedSparkline(self.speed_history, id="speed-sparkline")
            yield Static(T("Speed: ") + "0 files/s", id="status-speed")

            with Vertical(id="statuses"):
                yield Static(T("Elapsed: ") + "00d 00:00:00", classes="status", id="status-elapsed")
                yield Static(T("Files: ") + "0", classes="status", id="status-files")
                yield Static(T("Original: ") + "-", classes="status", id="status-original")
                yield Static(T("Deduplicated: ") + "-", classes="status", id="status-deduplicated")
                yield Static(T("Unchanged: ") + "0", classes="status", id="status-unchanged")
                yield Static(T("Modified: ") + "0", classes="status", id="status-modified")
                yield Static(T("Added: ") + "0", classes="status", id="status-added")
                yield Static(T("Other: ") + "0", classes="status", id="status-other")
                yield Static(T("Errors: ") + "0", classes="status errors-ok", id="status-errors")
                yield Static(T("Progress: "), classes="status", id="status-progress")
                yield Static(T("RC: ") + "RUNNING", classes="status", id="status-rc")

    def update_from_session(self, session):
        """Show the current state of the session."""
        self.elapsed_time = session.elapsed
        self.files_count = session.nfiles
        self.original_size = session.original_size
        self.deduplicated_size = session.deduplicated_size
        self.unchanged_count = session.count("U-")
        self.modified_count = session.count("M")
        self.added_count = session.count("A+")
        self.error_count = session.count("E")
        self.other_count = sum(session.files_stats.values()) - session.count("U-MA+E")
        self.progress_text = session.progress_text
        self.rc = session.rc

    def update_speed(self, files_per_second):
        """Add one sample to the speed sparkline."""
        self.files_per_second = files_per_second
        self.speed_history.append(files_per_second)
        self.speed_history = self.speed_history[-SpeedSparkline.HISTORY_SIZE :]
        # Use our custom update method
        self.query_one("#speed-sparkline").update_data(self.speed_history)
        self.query_one("#status-speed").update(T("Speed: ") + f"{files_per_second:.0f} files/s")

    @staticmethod
    def _format_size(size):
        return "-" if size is None else format_file_size(size)

    def watch_error_count(self, count: int) -> None:
        sw = self.query_one("#status-errors")
        if count == 0:
            sw.remove_class("errors-warning")
            sw.add_class("errors-ok")
        else:
            sw.remove_class("errors-ok")
            sw.add_class("errors-warning")
        sw.update(T("Errors: ") + str(count))

    def watch_files_count(self, count: int) -> None:
        self.query_one("#status-files").update(T("Files: ") + str(count))

    def watch_original_size(self, size) -> None:
        self.query_one("#status-original").update(T("Original: ") + self._format_size(size))

    def watch_deduplicated_size(self, size) -> None:
        self.query_one("#status-deduplicated").update(T("Deduplicated: ") + self._format_size(size))

    def watch_unchanged_count(self, count: int) -> None:
        self.query_one("#status-unchanged").update(T("Unchanged: ") + str(count))

    def watch_modified_count(self, count: int) -> None:
        self.query_one("#status-modified").update(T("Modified: ") + str(count))

    def watch_added_count(self, count: int) -> None:
        self.query_one("#status-added").update(T("Added: ") + str(count))

    def watch_other_count(self, count: int) -> None:
        self.query_one("#status-other").update(T("Other: ") + str(count))

    def watch_progress_text(self, text: str) -> None:
        label = T("Progress: ")
        # a wrapped line would push the lines below it out of the panel, thus the truncation.
        space = (self.size.width or 60) - len(label) - 1
        text = ellipsis_truncate(text, space).rstrip() if text else ""
        self.query_one("#status-progress").update(label + escape(text))

    def watch_rc(self, rc: int):
        label = self.query_one("#status-rc")
        if rc is None:
            label.update(T("RC: ") + "RUNNING")
            return

        label.remove_class("rc-ok")
        label.remove_class("rc-warning")
        label.remove_class("rc-error")

        status = classify_ec(rc)
        if status == "success":
            label.add_class("rc-ok")
        elif status == "warning":
            label.add_class("rc-warning")
        else:  # error, signal
            label.add_class("rc-error")

        label.update(T("RC: ") + str(rc))

    def watch_elapsed_time(self, elapsed: float) -> None:
        if TRANSLATOR.enabled:
            # There seems to be no official formula for stardates, so we make something up.
            # When showing the stardate, it is an absolute time, not relative "elapsed time".
            ut = time.time()
            sd = (ut - 1735689600) / 60.0  # Minutes since 2025-01-01 00:00.00 UTC
            msg = f"Stardate {sd:.1f}"
        else:
            seconds = int(elapsed)
            days, seconds = divmod(seconds, 86400)
            h, m, s = seconds // 3600, (seconds % 3600) // 60, seconds % 60
            msg = f"Elapsed: {days:02d}d {h:02d}:{m:02d}:{s:02d}"
        self.query_one("#status-elapsed").update(msg)

    def refresh_ui_labels(self):
        """Update static UI labels with current translation."""
        self.watch_elapsed_time(self.elapsed_time)
        self.watch_files_count(self.files_count)
        self.watch_original_size(self.original_size)
        self.watch_deduplicated_size(self.deduplicated_size)
        self.watch_unchanged_count(self.unchanged_count)
        self.watch_modified_count(self.modified_count)
        self.watch_added_count(self.added_count)
        self.watch_other_count(self.other_count)
        self.watch_error_count(self.error_count)
        self.watch_progress_text(self.progress_text)
        self.watch_rc(self.rc)
        self.query_one("#status-speed").update(T("Speed: ") + f"{self.files_per_second:.0f} files/s")


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
    # Styles for the log levels (and the prompts).
    LEVEL_STYLES = {
        "DEBUG": "dim",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "bold red",
        "PROMPT": "bold yellow",
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
