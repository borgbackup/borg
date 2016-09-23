import os
import time

import pytest

from ..remote import SleepingBandwidthLimiter


class TestSleepingBandwidthLimiter:
    def expect_write(self, fd, data):
        self.expected_fd = fd
        self.expected_data = data

    def check_write(self, fd, data):
        assert fd == self.expected_fd
        assert data == self.expected_data
        return len(data)

    def test_write_unlimited(self, monkeypatch):
        monkeypatch.setattr(os, "write", self.check_write)

        it = SleepingBandwidthLimiter(0)
        self.expect_write(5, b"test")
        it.write(5, b"test")

    def test_write(self, monkeypatch):
        monkeypatch.setattr(os, "write", self.check_write)
        monkeypatch.setattr(time, "monotonic", lambda: now)
        monkeypatch.setattr(time, "sleep", lambda x: None)

        now = 100

        it = SleepingBandwidthLimiter(100)

        # all fits
        self.expect_write(5, b"test")
        it.write(5, b"test")

        # only partial write
        self.expect_write(5, b"123456")
        it.write(5, b"1234567890")

        # sleeps
        self.expect_write(5, b"123456")
        it.write(5, b"123456")

        # long time interval between writes
        now += 10
        self.expect_write(5, b"1")
        it.write(5, b"1")

        # long time interval between writes, filling up quota
        now += 10
        self.expect_write(5, b"1")
        it.write(5, b"1")

        # long time interval between writes, filling up quota to clip to maximum
        now += 10
        self.expect_write(5, b"1")
        it.write(5, b"1")
