"""Cockpit UI translations."""

import os

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


SWEDISH_DICTIONARY = {  # English -> Swedish
    "**** You're welcome! ****": "**** Varsågod! ****",
    "Files: ": "Filer: ",
    "Unchanged: ": "Oförändrade: ",
    "Modified: ": "Ändrade: ",
    "Added: ": "Tillagda: ",
    "Other: ": "Övriga: ",
    "Errors: ": "Fel: ",
    "RC: ": "Returkod: ",
    "Speed: ": "Hastighet: ",
    "Elapsed: ": "Förfluten tid: ",
    "RC: RUNNING": "Returkod: KÖRS",
    "Log": "Logg",
    "Quit": "Avsluta",
    "Toggle Translator": "Växla Borg-språk",
    "Cockpit for BorgBackup": "Kontrollpanel för BorgBackup",
}


def get_language() -> str:
    """Return the requested Cockpit UI language, falling back to English."""
    language = os.environ.get("BORG_COCKPIT_LANGUAGE")
    if language is None:
        language = os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES") or os.environ.get("LANG", "")
    return language.split(".", maxsplit=1)[0].split("_", maxsplit=1)[0].lower()


class UniversalTranslator:
    """
    Handles translation of log messages.
    """

    def __init__(self, enabled: bool = True, language: str | None = None):
        # self.enabled is the opposite of "Translator active" on the TUI,
        # because in the source, we translate English to Borg.
        self.enabled = enabled  # True: English -> Borg
        self.language = language or get_language()

    def toggle(self):
        """Toggle translation state."""
        self.enabled = not self.enabled
        return self.enabled

    def translate(self, message: str) -> str:
        """Translate a message for the active Cockpit language."""
        dictionary = BORG_DICTIONARY if self.enabled else SWEDISH_DICTIONARY if self.language == "sv" else {}

        # Full matching first
        if message in dictionary:
            return dictionary[message]

        # Substring matching next
        for key, value in dictionary.items():
            if key in message:
                return message.replace(key, value)

        return message


# Global Instance
TRANSLATOR = UniversalTranslator(enabled=False)

# Global translation function
T = TRANSLATOR.translate
