#!/usr/bin/env python3
"""Regenerate FAME.md and FAME.svg, a contributor summary produced by git-fame.

FAME.md is the full table, FAME.svg a bar chart of the busiest contributors that
FAME.md embeds.  The chart is drawn here rather than taken from git-fame's own
`--format=svg`, which renders the whole table as monospaced text - fine for a
handful of contributors, unreadable for a few hundred.  It leaves out bots,
which do appear in the table.

Usage: python scripts/fame.py [--top N] [--svg-top N]

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

Both files are left alone if nothing but the generation date would change, so
that running this regularly (see .github/workflows/fame.yml) does not produce a
diff for a week in which the statistics did not move.
"""

import argparse
import json
import re
import subprocess
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

BRANCH = "master"

DATE_LINE = re.compile(r"^Generated on \d{4}-\d{2}-\d{2} ", re.MULTILINE)

# Bots keep their row in the table - they did make those commits - but they
# would take a slot away from a person in the chart, which only has room for a
# few.  GitHub appends "[bot]" to the account name of a bot, e.g.
# "dependabot[bot]"; matching that is safer than guessing from the name.
BOT = re.compile(r"\[bot\]$")

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

![Contributors by commit count](FAME.svg)

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


# Chart geometry, in user units.  The viewport is given in user units plus a
# viewBox rather than in em, because em on the root <svg> resolves against the
# font size that element inherits, not against the font size of the text inside.
SVG_TOP = 20  # a chart of all 300+ contributors would be unreadable
SVG_WIDTH = 760
SVG_ROW_H = 22
SVG_PAD = 14
SVG_LABEL_W = 240  # x where the bars start, i.e. width of the name column
SVG_COUNT_W = 70  # right hand column holding the commit count
SVG_HEAD_H = 58
SVG_FOOT_H = 26
SVG_NAME_MAX = 32  # characters that fit into the name column

# Fills are set per class so that the chart can follow the reader's colour
# scheme; GitHub renders the file in an <img>, where the media query applies.
# The bars use the green of the logo (docs/_static/logo.svg).  That green is
# made for a dark background - on white it only reaches a contrast of 1.9:1,
# below the 3:1 that WCAG asks for graphics - so the light scheme darkens it
# while keeping the hue.
SVG_STYLE = """\
<style>
    text { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif }
    .bg { fill: #ffffff }
    .title { font-size: 16px; font-weight: 600; fill: #1f2328 }
    .name { font-size: 12px; fill: #1f2328 }
    .subtitle, .footer, .count { font-size: 11px; fill: #59636e }
    .count { font-size: 12px; text-anchor: end }
    .bar { fill: #00a000 }
    @media (prefers-color-scheme: dark) {
        .bg { fill: #0d1117 }
        .title, .name { fill: #e6edf3 }
        .subtitle, .footer, .count { fill: #9198a1 }
        .bar { fill: #00dd00 }
    }
</style>"""


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


def shorten(name):
    """Truncate `name` to what fits into the name column of the chart."""
    return name if len(name) <= SVG_NAME_MAX else name[: SVG_NAME_MAX - 1] + "…"


def render_svg(rows, contributors):
    """Return an SVG bar chart of `rows`, the busiest out of `contributors` people."""
    height = SVG_HEAD_H + len(rows) * SVG_ROW_H + SVG_FOOT_H
    bars = SVG_WIDTH - SVG_LABEL_W - SVG_COUNT_W - SVG_PAD
    most_commits = rows[0][1]
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{SVG_WIDTH}" height="{height}"'
        f' viewBox="0 0 {SVG_WIDTH} {height}" role="img"'
        f' aria-label="Borg contributors by commit count">',
        SVG_STYLE,
        f'<rect class="bg" x="0" y="0" width="{SVG_WIDTH}" height="{height}" rx="6"/>',
        f'<text class="title" x="{SVG_PAD}" y="26">Borg contributors</text>',
        f'<text class="subtitle" x="{SVG_PAD}" y="44">'
        f"top {len(rows)} of {contributors:,} by commits on the {BRANCH} branch</text>",
    ]
    for i, (name, commits, _loc, _files) in enumerate(rows):
        y = SVG_HEAD_H + i * SVG_ROW_H
        baseline = y + int(SVG_ROW_H * 0.7)
        # the scale is linear, but a bar should stay visible however short it is
        width = max(2, round(bars * commits / most_commits))
        # names are commit-controlled input, so & and < would break the XML
        out.append(f'<text class="name" x="{SVG_PAD}" y="{baseline}">{escape(shorten(name))}</text>')
        out.append(
            f'<rect class="bar" x="{SVG_LABEL_W}" y="{y + 5}" width="{width}" height="{SVG_ROW_H - 10}" rx="2"/>'
        )
        out.append(f'<text class="count" x="{SVG_WIDTH - SVG_PAD}" y="{baseline}">{commits:,}</text>')
    out.append(
        f'<text class="footer" x="{SVG_PAD}" y="{height - 10}">generated by scripts/fame.py using git-fame</text>'
    )
    out.append("</svg>")
    return "\n".join(out) + "\n"


def same_statistics(old, new):
    """Return True if the two FAME.md contents differ only in the generation date."""
    return DATE_LINE.sub("Generated on ", old) == DATE_LINE.sub("Generated on ", new)


def update(path, new, unchanged=str.__eq__):
    """Write `new` to `path` unless `unchanged` says it is already there."""
    if path.exists() and unchanged(path.read_text(encoding="utf-8"), new):
        print(f"{path} is up to date")
        return
    path.write_text(new, encoding="utf-8")
    print(f"wrote {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--top", type=int, default=0, metavar="N", help="only list the top N contributors")
    parser.add_argument(
        "--svg-top", type=int, default=SVG_TOP, metavar="N", help="chart the top N contributors [default: %(default)s]"
    )
    args = parser.parse_args()

    repo = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())
    rows, total = collect()
    contributors = len(rows)
    people = [row for row in rows if not BOT.search(row[0])]
    if args.top:
        rows = rows[: args.top]
    print(f"{len(rows)} of {contributors} contributors, {contributors - len(people)} of them bots")
    update(repo / "FAME.md", render(rows, total, contributors), unchanged=same_statistics)
    update(repo / "FAME.svg", render_svg(people[: args.svg_top], len(people)))


if __name__ == "__main__":
    main()
