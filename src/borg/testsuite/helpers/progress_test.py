from ...helpers.progress import ProgressIndicatorPercent


def test_progress_percentage(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel("INFO")
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == "  0%\n"
    pi.show(420)
    pi.show(680)
    out, err = capfd.readouterr()
    assert err == " 42%\n 68%\n"
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == "100%\n"
    pi.finish()
    out, err = capfd.readouterr()
    assert err == "\n"


def test_progress_percentage_step(capfd):
    pi = ProgressIndicatorPercent(100, step=2, start=0, msg="%3.0f%%")
    pi.logger.setLevel("INFO")
    pi.show()
    out, err = capfd.readouterr()
    assert err == "  0%\n"
    pi.show()
    out, err = capfd.readouterr()
    assert err == ""  # no output at 1% as we have step == 2
    pi.show()
    out, err = capfd.readouterr()
    assert err == "  2%\n"


def test_progress_percentage_quiet(capfd):
    pi = ProgressIndicatorPercent(1000, step=5, start=0, msg="%3.0f%%")
    pi.logger.setLevel("WARN")
    pi.show(0)
    out, err = capfd.readouterr()
    assert err == ""
    pi.show(1000)
    out, err = capfd.readouterr()
    assert err == ""
    pi.finish()
    out, err = capfd.readouterr()
    assert err == ""
