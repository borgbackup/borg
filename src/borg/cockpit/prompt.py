"""
Borg Cockpit - modal dialogs: borg's yes/no prompts and the confirmation for quitting while borg runs.
"""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from .widgets import printable


class PromptModal(ModalScreen[str]):
    """
    Shows the message of a question_prompt and returns the answer to send to borg's stdin.

    The buttons send YES / NO, which borg accepts for all its prompts, including the "Type 'YES'" ones.
    The input field is for anything else, e.g. an empty answer to select the default.
    """

    def __init__(self, message):
        super().__init__()
        self.message = printable(message, multiline=True)  # it can contain paths, archive names, ...

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt-dialog"):
            yield Static(self.message, id="prompt-message", markup=False)
            yield Input(placeholder="other answer, Enter sends it", id="prompt-input")
            with Horizontal(id="prompt-buttons"):
                yield Button("YES", id="prompt-yes", variant="success")
                yield Button("NO", id="prompt-no", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss("YES" if event.button.id == "prompt-yes" else "NO")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)


class ConfirmQuitModal(ModalScreen[bool]):
    """
    Asks whether to really quit while borg is still running, because quitting terminates borg.

    Returns True to terminate borg and quit. The harmless button comes first, so it has the focus
    and Enter selects it; Escape means the same.
    """

    BINDINGS = [
        ("y", "answer(True)", "Terminate borg and quit"),
        ("n", "answer(False)", "Continue"),
        ("escape", "answer(False)", "Continue"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt-dialog"):
            yield Static(
                "borg is still running. Quitting the cockpit terminates it.", id="prompt-message", markup=False
            )
            with Horizontal(id="prompt-buttons"):
                yield Button("Continue (n)", id="quit-no", variant="success")
                yield Button("Terminate borg and quit (y)", id="quit-yes", variant="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "quit-yes")

    def action_answer(self, terminate: bool) -> None:
        self.dismiss(terminate)
