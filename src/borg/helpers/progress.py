import logging
import json
import os
import sys
import time
from shutil import get_terminal_size

from .parseformat import ellipsis_truncate
from ..logger import create_logger, JSONProgressFormatter

logger = create_logger()

DEFAULT_PROGRESS_FPS = 5.0  # progress updates per second, the traditional rate

_warned_fps: set[str] = set()  # invalid BORG_PROGRESS_FPS values already complained about


def get_progress_dt():
    """Minimum time between progress updates [seconds], 1 / BORG_PROGRESS_FPS [updates per second]."""
    fps_str = os.environ.get("BORG_PROGRESS_FPS", "").strip()
    if fps_str:
        try:
            fps = float(fps_str)
        except ValueError:
            fps = 0.0
        if fps > 0.0:
            return 1.0 / fps
        if fps_str not in _warned_fps:
            _warned_fps.add(fps_str)
            logger.warning(f"Invalid BORG_PROGRESS_FPS value {fps_str!r}, must be a number > 0. Ignoring it.")
    return 1.0 / DEFAULT_PROGRESS_FPS


class ProgressIndicatorBase:
    LOGGER = "borg.output.progress"
    JSON_TYPE: str = None

    operation_id_counter = 0

    @classmethod
    def operation_id(cls):
        """Unique number, can be used by receiving applications to distinguish different operations."""
        cls.operation_id_counter += 1
        return cls.operation_id_counter

    def __init__(self, msgid=None):
        self.logger = logging.getLogger(self.LOGGER)
        self.id = self.operation_id()
        self.msgid = msgid

    def make_json(self, *, finished=False, **kwargs):
        kwargs |= dict(operation=self.id, msgid=self.msgid, type=self.JSON_TYPE, finished=finished, time=time.time())
        return json.dumps(kwargs)

    def finish(self):
        j = self.make_json(message="", finished=True)
        self.logger.info(j)


class ProgressIndicatorMessage(ProgressIndicatorBase):
    JSON_TYPE = "progress_message"

    def output(self, msg):
        j = self.make_json(message=msg)
        self.logger.info(j)


class ProgressIndicatorPercent(ProgressIndicatorBase):
    JSON_TYPE = "progress_percent"

    def __init__(self, total=0, step=5, start=0, msg="%3.0f%%", msgid=None):
        """
        Percentage-based progress indicator.

        :param total: total amount of items.
        :param step: step size in percent.
        :param start: at which percent value to start.
        :param msg: output message; must contain one %f placeholder for the percentage.
        """
        self.counter = 0  # 0 .. (total-1)
        self.total = total
        self.trigger_at = start  # output next percentage value when reaching (at least) this
        self.step = step
        self.msg = msg

        super().__init__(msgid=msgid)

    def progress(self, current=None, increase=1):
        if current is not None:
            self.counter = current
        pct = self.counter * 100 / self.total
        self.counter += increase
        if pct >= self.trigger_at:
            self.trigger_at += self.step
            return pct

    def show(self, current=None, increase=1, info=None):
        """
        Show and output the progress message.

        :param current: Set the current percentage. [None]
        :param increase: Increase the current percentage. [None]
        :param info: Array of strings to be formatted with msg. [None]
        """
        pct = self.progress(current, increase)
        if pct is not None:
            if info is not None:
                return self.output(self.msg % tuple([pct] + info), info=info)
            else:
                return self.output(self.msg % pct)

    def output(self, message, info=None):
        j = self.make_json(message=message, current=self.counter, total=self.total, info=info)
        self.logger.info(j)


# borg green, as on borgbackup.org: #22D045
GREEN_TRUECOLOR = "\x1b[38;2;34;208;69m"
# The nearest xterm-256 entry (41 == #00d75f) drops the red channel and reads cooler and more
# acid than the brand green, so we rather use the bright green from the terminal's own palette:
# it behaves better on light backgrounds and on other people's terminals.
GREEN_16 = "\x1b[92m"
ANSI_RESET = "\x1b[0m"
ANSI_HIDE_CURSOR = "\x1b[?25l"
ANSI_SHOW_CURSOR = "\x1b[?25h"
ANSI_CLEAR_LINE = "\r\x1b[2K"  # carriage return, then erase the whole line

# All frames have East Asian Width "Neutral", so they occupy exactly one cell each and the
# message after the spinner never shifts column while the animation runs.
SPINNER_FRAMES = {
    "square": "▫▪◻◼",  # ▫ ▪ ◻ ◼ - pulsing: small to medium, hollow to solid
    "cube": "◰◳◲◱",  # ◰ ◳ ◲ ◱ - quadrant rotating clockwise
    "boxed": "⊞⊠⊟⊡",  # ⊞ ⊠ ⊟ ⊡ - squared plus/times/minus/dot
    "ascii": "|/-\\",  # the classic, for terminals that can not encode the above
}
DEFAULT_SPINNER = "square"


def _encodable(text, stream):
    """Can <text> be represented in the encoding of <stream>?"""
    try:
        text.encode(getattr(stream, "encoding", None) or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _progress_output_is_json():
    """Is progress output currently rendered as JSON (--log-json)?"""
    progress_logger = logging.getLogger(ProgressIndicatorBase.LOGGER)
    return any(isinstance(handler.formatter, JSONProgressFormatter) for handler in progress_logger.handlers)


def spinner_colour(stream):
    """The ANSI sequence for borg green, or "" if colour is unwanted on <stream>."""
    if os.environ.get("NO_COLOR") is not None:
        return ""
    if os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return GREEN_TRUECOLOR
    return GREEN_16


class ProgressIndicatorSpinner(ProgressIndicatorBase):
    """
    Progress indicator for operations of unknown duration or unknown size.

    Nothing is counted here, the spinner just shows that borg is still working (and, via the
    message, at what). It is pull-based on purpose: no thread, no timer, nothing runs while the
    caller is not calling. show() is rate limited to BORG_PROGRESS_FPS internally, so calling it
    very often is cheap: it costs one time.monotonic() per call and repaints at most that often.

    On a terminal, the spinner frame and the message are repainted in place, in borg green.
    Without a terminal (or with --log-json), an animation is pointless, so nothing is repainted:
    only message changes are logged, in the same way ProgressIndicatorMessage does it.

    Usage:

        with ProgressIndicatorSpinner("Deduplicating", msgid="create") as spinner:
            for chunk in chunks:
                process(chunk)
                spinner.show()

    Without the context manager, call finish() yourself - it clears the spinner line and
    switches the terminal's cursor back on.

    Set BORG_SPINNER=off to never animate, BORG_SPINNER=ascii to force the ASCII frames.
    """

    JSON_TYPE = "progress_message"  # same contract as ProgressIndicatorMessage, see frontends docs

    def __init__(self, message="", *, frames=DEFAULT_SPINNER, msgid=None, stream=None, animate=None):
        """
        :param message: text shown next to the spinner, can be updated via show(message).
        :param frames: name of a SPINNER_FRAMES set, or a string of frame characters.
        :param msgid: see ProgressIndicatorBase.
        :param stream: where to paint the animation [sys.stderr, looked up when writing].
        :param animate: force the animation on or off [None: decide by looking at the output].
        """
        super().__init__(msgid=msgid)
        self.message = message
        self._stream = stream
        mode = os.environ.get("BORG_SPINNER", "").lower()
        frames = SPINNER_FRAMES.get(frames, frames)
        self.frames = SPINNER_FRAMES["ascii"] if mode == "ascii" or not _encodable(frames, self.stream) else frames
        self.animate = self._animation_wanted(mode) if animate is None else animate
        self.colour = spinner_colour(self.stream) if self.animate else ""
        self.reset = ANSI_RESET if self.colour else ""
        self.index = 0  # index of the next frame to paint
        self.next_update = 0.0  # time.monotonic() value from which on the next output is due
        self.painted = False  # is there a spinner line on the terminal right now?
        self.started = False  # did we output anything yet?

    @property
    def stream(self):
        """Like logger.StderrHandler, use whatever sys.stderr is *now*, not at construction time."""
        return sys.stderr if self._stream is None else self._stream

    def _animation_wanted(self, mode):
        if mode == "off":
            return False
        if os.environ.get("TERM", "") in ("", "dumb"):
            return False
        try:
            if not self.stream.isatty():
                return False
        except (OSError, ValueError):  # closed or otherwise unusable stream
            return False
        return not _progress_output_is_json()

    def show(self, message=None):
        """Advance the spinner, optionally updating the message. Cheap to over-call."""
        changed = message is not None and message != self.message
        if message is not None:
            self.message = message
        now = time.monotonic()
        if now < self.next_update:
            return
        if self.animate:
            self.next_update = now + get_progress_dt()
            self.paint()
        elif changed or not self.started:
            # no terminal to animate on: only say something if there is something new to say.
            self.next_update = now + get_progress_dt()
            self.started = True
            self.output(self.message)

    def paint(self):
        """Repaint the spinner line in place."""
        if not self.logger.isEnabledFor(logging.INFO):  # e.g. --quiet
            return
        frame = self.frames[self.index % len(self.frames)]
        self.index += 1
        # a wrapped line could not be repainted in place, thus the truncation.
        # ellipsis_truncate pads short messages to the full width - we erase the line instead.
        columns, lines = get_terminal_size()
        message = ellipsis_truncate(self.message, columns - 2).rstrip(" ") if self.message else ""
        text = f"{self.colour}{frame}{self.reset} {message}" if message else f"{self.colour}{frame}{self.reset}"
        self.write(("" if self.painted else ANSI_HIDE_CURSOR) + ANSI_CLEAR_LINE + text)
        self.painted = True
        self.started = True

    def write(self, text):
        try:
            self.stream.write(text)
            self.stream.flush()
        except (OSError, ValueError):  # the stream went away, e.g. a closed pipe
            self.animate = False

    def output(self, message):
        j = self.make_json(message=message)
        self.logger.info(j)

    def finish(self):
        """Remove the spinner line from the terminal / log that the operation is finished."""
        if self.animate:
            if self.painted:
                self.write(ANSI_CLEAR_LINE + ANSI_SHOW_CURSOR)
                self.painted = False
            # no JSON "finished" record here: if we animate, nobody is parsing our output anyway
            # and the empty line the text formatter would emit for it is just in the way.
        else:
            super().finish()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.finish()
        return False
