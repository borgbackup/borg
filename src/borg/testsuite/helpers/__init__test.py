import pytest

from ...constants import *  # NOQA
from ...helpers import classify_ec, max_ec


@pytest.mark.parametrize(
    "ec_range,ec_class",
    (
        # inclusive range start, exclusive range end
        ((0, 1), "success"),
        ((1, 2), "warning"),
        ((2, 3), "error"),
        ((EXIT_ERROR_BASE, EXIT_WARNING_BASE), "error"),
        ((EXIT_WARNING_BASE, EXIT_SIGNAL_BASE), "warning"),
        ((EXIT_SIGNAL_BASE, 256), "signal"),
    ),
)
def test_classify_ec(ec_range, ec_class):
    for ec in range(*ec_range):
        classify_ec(ec) == ec_class


def test_ec_invalid():
    with pytest.raises(ValueError):
        classify_ec(666)
    with pytest.raises(ValueError):
        classify_ec(-1)
    with pytest.raises(TypeError):
        classify_ec(None)


@pytest.mark.parametrize(
    "ec1,ec2,ec_max",
    (
        # same for modern / legacy
        (EXIT_SUCCESS, EXIT_SUCCESS, EXIT_SUCCESS),
        (EXIT_SUCCESS, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        # legacy exit codes
        (EXIT_SUCCESS, EXIT_WARNING, EXIT_WARNING),
        (EXIT_SUCCESS, EXIT_ERROR, EXIT_ERROR),
        (EXIT_WARNING, EXIT_SUCCESS, EXIT_WARNING),
        (EXIT_WARNING, EXIT_WARNING, EXIT_WARNING),
        (EXIT_WARNING, EXIT_ERROR, EXIT_ERROR),
        (EXIT_WARNING, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        (EXIT_ERROR, EXIT_SUCCESS, EXIT_ERROR),
        (EXIT_ERROR, EXIT_WARNING, EXIT_ERROR),
        (EXIT_ERROR, EXIT_ERROR, EXIT_ERROR),
        (EXIT_ERROR, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        # some modern codes
        (EXIT_SUCCESS, EXIT_WARNING_BASE, EXIT_WARNING_BASE),
        (EXIT_SUCCESS, EXIT_ERROR_BASE, EXIT_ERROR_BASE),
        (EXIT_WARNING_BASE, EXIT_SUCCESS, EXIT_WARNING_BASE),
        (EXIT_WARNING_BASE + 1, EXIT_WARNING_BASE + 2, EXIT_WARNING_BASE + 1),
        (EXIT_WARNING_BASE, EXIT_ERROR_BASE, EXIT_ERROR_BASE),
        (EXIT_WARNING_BASE, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
        (EXIT_ERROR_BASE, EXIT_SUCCESS, EXIT_ERROR_BASE),
        (EXIT_ERROR_BASE, EXIT_WARNING_BASE, EXIT_ERROR_BASE),
        (EXIT_ERROR_BASE + 1, EXIT_ERROR_BASE + 2, EXIT_ERROR_BASE + 1),
        (EXIT_ERROR_BASE, EXIT_SIGNAL_BASE, EXIT_SIGNAL_BASE),
    ),
)
def test_max_ec(ec1, ec2, ec_max):
    assert max_ec(ec1, ec2) == ec_max
