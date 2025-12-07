"""
Universal Translator - Converts standard English into Borg Speak.
"""

BORG_DICTIONARY = {  # English -> Borg
    # UI Strings
    "**** You're welcome! ****": "You will be assimilated! ",
    "Files: ": "Drones: ",
    "Unchanged: ": "Unchanged: ",
    "Modified: ": "Modified: ",
    "Added: ": "Assimilated: ",
    "Other: ": "Other: ",
    "Errors: ": "Escaped: ",
    "RC: ": "Termination Code: ",
    "Log": "Subspace Transmissions",
}


class UniversalTranslator:
    """
    Handles translation of log messages.
    """

    def __init__(self, enabled: bool = True):
        # self.enabled is the opposite of "Translator active" on the TUI,
        # because in the source, we translate English to Borg.
        self.enabled = enabled  # True: English -> Borg

    def toggle(self):
        """Toggle translation state."""
        self.enabled = not self.enabled
        return self.enabled

    def translate(self, message: str) -> str:
        """Translate a message if enabled."""
        if not self.enabled:
            return message

        # Full matching first
        if message in BORG_DICTIONARY:
            return BORG_DICTIONARY[message]

        # Substring matching next
        for key, value in BORG_DICTIONARY.items():
            if key in message:
                return message.replace(key, value)

        return message


# Global Instance
TRANSLATOR = UniversalTranslator(enabled=False)

# Global translation function
T = TRANSLATOR.translate
