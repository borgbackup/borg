#!/usr/bin/env python3
"""Regenerate FAME.md, a contributor summary produced by git-fame.

Usage: python scripts/fame.py [--top N]

Requires `git-fame` (pip install git-fame) and a full (non-shallow) clone,
because the line counts come from `git blame` over the whole history.

The statistics always describe the master branch, no matter which branch the
script is run from, so that FAME.md does not change depending on the checkout.

Contributors are sorted by commit count.  git-fame also reports "surviving"
lines of code, i.e. lines of the current checkout that `git blame` attributes
to an author; that is useful context, but it silently discounts work that was
later refactored away, so it is not what we rank by.

Author identities are merged via .mailmap, so fix duplicates there rather than
here.
"""

import argparse
import json
import subprocess
from datetime import date
from pathlib import Path

BRANCH = "master"

# Generated and binary-ish files would drown out hand-written code.  Excalidraw
# scenes are the worst offenders: they are pretty-printed JSON, so a single
# diagram of a few boxes and arrows is over 10000 lines.  Image formats are
# listed for good measure - git-fame skips binary files by itself, but .svg is
# text and would count.
EXCLUDE = r".*\.(excalidraw|png|jpg|jpeg|gif|svg|ico)$"

HEADERS = ("Contributor", "Commits", "Lines", "Files")

PREAMBLE = """\
# Contributors

{count} people have contributed to Borg, with {commits} commits in total.
Thanks to everyone who helped!

Generated on {date} by `scripts/fame.py`, which computes the statistics with
[git-fame](https://github.com/casperdcl/git-fame), from the `{branch}` branch
only - commits that exist solely on other branches or in unmerged pull requests
are not counted.

This list is only a rough summary: it counts commits and lines, which say
nothing about reviews, bug reports, translations, documentation review, support
work or funding.  See `AUTHORS` for a manually maintained list of contributors.

"Lines" are surviving lines of code: lines of the current master that
`git blame` attributes to that author.  Code that was later rewritten does not
show up there, so the number understates early contributions.  Generated files
(such as the Excalidraw sources of the documentation figures) are excluded.

"""


def collect():
    """Run git-fame and return (rows, total), all contributors, most commits first."""
    out = subprocess.check_output(
        ["git-fame", "--silent-progress", "--format=json", "--sort=commits", f"--excl={EXCLUDE}", f"--branch={BRANCH}"],
        text=True,
    )
    fame = json.loads(out)
    rows = [(name, commits, loc, files) for name, loc, commits, files, *_percentages in fame["data"]]
    return rows, fame["total"]


def render(rows, total, contributors):
    """Return the full FAME.md contents, listing `rows` out of `contributors` people."""
    preamble = PREAMBLE.format(
        count=f"{contributors:,}", commits=f"{total['commits']:,}", date=date.today().isoformat(), branch=BRANCH
    )
    if len(rows) < contributors:
        preamble += f"Only the top {len(rows):,} contributors by commit count are listed here.\n\n"
    table = ["| " + " | ".join(HEADERS) + " |", "|:---" + "|---:" * (len(HEADERS) - 1) + "|"]
    for name, commits, loc, files in rows:
        # escape the markdown table delimiter, names are commit-controlled input
        escaped = name.replace("|", "\\|")
        table.append(f"| {escaped} | {commits:,} | {loc:,} | {files:,} |")
    return preamble + "\n".join(table) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top", type=int, default=0, metavar="N", help="only list the top N contributors")
    args = parser.parse_args()

    repo = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    rows, total = collect()
    contributors = len(rows)
    if args.top:
        rows = rows[: args.top]
    output = repo / "FAME.md"
    output.write_text(render(rows, total, contributors), encoding="utf-8")
    print(f"wrote {output} ({len(rows)} of {contributors} contributors)")


if __name__ == "__main__":
    main()
