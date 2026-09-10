"""
Borg Cockpit - modal dialog for borg's yes/no prompts.
"""

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static


class PromptModal(ModalScreen[str]):
    """
    Shows the message of a question_prompt and returns the answer to send to borg's stdin.

    The buttons send YES / NO, which borg accepts for all its prompts, including the "Type 'YES'" ones.
    The input field is for anything else, e.g. an empty answer to select the default.
    """

    def __init__(self, message):
        super().__init__()
        self.message = message

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
