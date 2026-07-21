"""Generate the data set that is backed up in the borg2 demo screencast.

Requirements for this data (see #6303):

- it must be compressible, so that the compression borg does is actually
  visible in the screencast (do not use e.g. jpeg images for this).
- it must not be trivially repetitive, or deduplication would look much better
  in the screencast than it is for real-world data.

So we generate notes, log files and a database dump that look like the real
thing: recurring structure (timestamps, log levels, SQL statements) and words
drawn from a zipf-ish distribution, so that lz4 (borg's default compression)
gets a realistic ratio out of it. The seed is fixed, so that re-recordings
stay comparable.
"""

import itertools
import os
import random
import sys

SEED = 20260721

# How much data we generate - keep this small enough so that "borg create" does
# not take longer than a few seconds in the screencast. Also keep every single
# file below 100MB, or the size column of "borg list" is not aligned any more.
NOTES_FILES = 250
NOTES_SIZE = 100 * 1000 * 1000
LOGS_FILES = 12
LOGS_SIZE = 300 * 1000 * 1000
DUMP_SIZE = 90 * 1000 * 1000

BATCH = 100000  # words generated at once

LOG_LEVELS = ["DEBUG", "INFO", "INFO", "INFO", "WARNING", "ERROR"]
SERVICES = ["auth", "api", "worker", "scheduler", "storage", "mailer"]
CITIES = ["Berlin", "Hamburg", "Muenchen", "Koeln", "Leipzig", "Dresden"]


def vocabulary(rnd, count=2048):
    """A word list plus cumulative weights, so that some words are much more common than others."""
    words = ["".join(rnd.choices("abcdefghijklmnopqrstuvwxyz", k=rnd.randint(3, 10))) for _ in range(count)]
    cum_weights = list(itertools.accumulate(1.0 / (i + 1) for i in range(count)))
    return words, cum_weights


class WordSource:
    """Hands out random words, generating them in batches (which is a lot faster)."""

    def __init__(self, rnd, vocab):
        self.rnd = rnd
        self.words, self.cum_weights = vocab
        self.batch = []

    def get(self, count):
        while len(self.batch) < count:
            self.batch.extend(self.rnd.choices(self.words, cum_weights=self.cum_weights, k=BATCH))
        result = self.batch[:count]
        del self.batch[:count]
        return result


def write_file(path, size, make_line):
    written = 0
    with open(path, "w") as f:
        while written < size:
            lines = [make_line() for _ in range(1000)]
            data = "\n".join(lines) + "\n"
            f.write(data)
            written += len(data)


def main(destination):
    rnd = random.Random(SEED)
    src = WordSource(rnd, vocabulary(rnd))

    def note_line():
        return " ".join(src.get(rnd.randint(6, 14)))

    def log_line():
        return "2026-%02d-%02d %02d:%02d:%02d %-7s [%s] request_id=%08x user=%s %s" % (
            rnd.randint(1, 12),
            rnd.randint(1, 28),
            rnd.randint(0, 23),
            rnd.randint(0, 59),
            rnd.randint(0, 59),
            rnd.choice(LOG_LEVELS),
            rnd.choice(SERVICES),
            rnd.getrandbits(32),
            src.get(1)[0],
            " ".join(src.get(rnd.randint(4, 12))),
        )

    def sql_line():
        name, street = src.get(2)
        return (
            "INSERT INTO customers (id, name, email, street, city) VALUES (%d, '%s', '%s@example.com', '%s %d', '%s');"
            % (rnd.randint(1, 10**7), name, name, street, rnd.randint(1, 200), rnd.choice(CITIES))
        )

    notes = os.path.join(destination, "notes")
    os.makedirs(notes, exist_ok=True)
    for i in range(NOTES_FILES):
        write_file(os.path.join(notes, "note-%03d.txt" % i), NOTES_SIZE // NOTES_FILES, note_line)

    logs = os.path.join(destination, "logs")
    os.makedirs(logs, exist_ok=True)
    for i in range(LOGS_FILES):
        write_file(os.path.join(logs, "server-%02d.log" % i), LOGS_SIZE // LOGS_FILES, log_line)

    write_file(os.path.join(destination, "database-dump.sql"), DUMP_SIZE, sql_line)


if __name__ == "__main__":
    main(sys.argv[1])
