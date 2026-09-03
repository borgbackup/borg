from borg.cockpit.translator import UniversalTranslator


def test_swedish_cockpit_translations():
    translator = UniversalTranslator(enabled=False, language="sv")

    assert translator.translate("Log") == "Logg"
    assert translator.translate("Files: 3") == "Filer: 3"
    assert translator.translate("Cockpit for BorgBackup 2.0") == "Kontrollpanel för BorgBackup 2.0"


def test_english_is_the_default_language():
    translator = UniversalTranslator(enabled=False, language="en")

    assert translator.translate("Files: 3") == "Files: 3"


def test_borg_mode_takes_precedence_over_locale():
    translator = UniversalTranslator(enabled=True, language="sv")

    assert translator.translate("Files: 3") == "Drones: 3"
