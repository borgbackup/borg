#!/usr/bin/env python3
"""
Find the input size above which multi-threaded blake3 is worth using on THIS machine.

blake3 can hash a single input in parallel (max_threads=AUTO), but the speedup is not
monotonic in input size: it parallelises over its binary hash tree, so it spikes at powers
of two and decays in between, and for small inputs the thread dispatch costs more than it
saves - on some machines by a factor of 5 or more. The size where it starts paying off
depends on the core count, so it has to be measured per machine.

This script sweeps input sizes, measures single-threaded vs AUTO, and reports the smallest
size from which AUTO never loses. Points that would set the threshold are automatically
re-measured with more runs, so a single scheduling hiccup does not skew the result.

    scripts/blake3-optimize-mt-threshold.py                 # ~15s, recommended threshold
    scripts/blake3-optimize-mt-threshold.py --html --open   # ...and a chart in the browser
    scripts/blake3-optimize-mt-threshold.py --thorough      # 16 KiB steps, several minutes

Only needs the "blake3" package, which borg already depends on.
"""

import argparse
import json
import math
import os
import platform
import statistics
import sys
import tempfile
import time
import webbrowser

try:
    from blake3 import blake3
except ImportError:
    raise SystemExit("this script needs the 'blake3' package: pip install blake3")

KB = 1024
MB = 1024 * KB

# keep in sync with BLAKE3_MT_THRESHOLD_KIB in src/borg/crypto/key.py
BORG_DEFAULT_THRESHOLD_KIB = 256

# Sizes to measure, in KiB.
#
# These ladders deliberately avoid being made of round numbers. The speedup peaks at powers
# of two, so a ladder of powers of two samples only the best points and reports a threshold
# that is far too low. Every ladder therefore includes odd offsets and, in particular, sizes
# just *below* a power of two - the local worst cases.
LADDERS = {
    "quick": [8, 48, 96, 144, 192, 240, 256, 384, 496, 512, 768, 1008, 1024, 1536, 2048],
    "balanced": [
        4,
        8,
        12,
        16,
        24,
        32,
        48,
        64,
        80,
        96,
        112,
        128,
        144,
        160,
        176,
        192,
        208,
        224,
        240,
        256,
        288,
        320,
        352,
        368,
        384,
        416,
        448,
        480,
        496,
        512,
        576,
        640,
        704,
        768,
        832,
        896,
        960,
        1008,
        1024,
        1280,
        1536,
        1792,
        2032,
        2048,
        3072,
        4096,
    ],
    "thorough": [4, 8, 12, 16, 24, 32, 48, 64, 80, 96, 112] + list(range(128, 2049, 16)),
}


def machine_info():
    try:
        ncpu = len(os.sched_getaffinity(0))  # respects cgroup/taskset limits
    except AttributeError:
        ncpu = os.cpu_count() or 1
    info = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or platform.machine(),
        "cpus_available": ncpu,
        "cpus_total": os.cpu_count() or 1,
        "python": platform.python_version(),
        "blake3": getattr(sys.modules["blake3"], "__version__", "unknown"),
    }
    if sys.platform == "darwin":
        import subprocess

        try:
            info["processor"] = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=5
            ).stdout.strip()
        except Exception:
            pass
    return info


def measure(data, key, max_threads, runs, bytes_per_run):
    """Median MiB/s over <runs> timed repetitions, plus the observed spread."""
    reps = max(16, int(bytes_per_run / len(data)))
    for _ in range(min(100, reps)):  # warm up: let the thread pool spin up and caches fill
        blake3(data, key=key, max_threads=max_threads).digest()
    rates = []
    for _ in range(runs):
        t0 = time.perf_counter()
        for _ in range(reps):
            blake3(data, key=key, max_threads=max_threads).digest()
        rates.append(len(data) * reps / MB / (time.perf_counter() - t0))
    return statistics.median(rates), min(rates), max(rates)


def sample(kib, key, runs, bytes_per_run, pool):
    size = kib * KB
    data = pool[:size]
    single, _, _ = measure(data, key, 1, runs, bytes_per_run)
    auto, lo, hi = measure(data, key, blake3.AUTO, runs, bytes_per_run)
    return {
        "kib": kib,
        "single": single,
        "auto": auto,
        "ratio": auto / single,
        # a wide spread means the machine was busy; the caller may want to re-measure
        "noise": (hi - lo) / hi if hi else 0.0,
    }


def threshold_from(results, margin):
    """Smallest measured size from which every larger size is at least <margin>x."""
    ordered = sorted(results, key=lambda r: r["kib"])
    best = None
    for i, r in enumerate(ordered):
        if all(q["ratio"] >= margin for q in ordered[i:]):
            best = r["kib"]
            break
    return best


def blocker_below(results, threshold, margin):
    """The largest size still below <margin> - the point that forces the threshold up."""
    below = [r for r in results if r["kib"] < (threshold or math.inf) and r["ratio"] < margin]
    return max(below, key=lambda r: r["kib"]) if below else None


def adversarial_probes(threshold, max_kib, measured):
    """Sizes at or above <threshold> that are likely to be local minima of the sawtooth.

    Because the speedup peaks at powers of two, a candidate threshold picked from a sparse
    ladder is optimistic: the ladder may simply have missed the dips. Probe the sizes that
    tend to be worst - just below each power of two, and quarter-offsets in between - to try
    to disprove the candidate before reporting it.
    """
    probes = set()
    p = 1
    while p <= max_kib * 2:
        for delta in (16, 48, 112):  # just below a peak: the local worst case
            v = p - delta
            if threshold <= v <= max_kib:
                probes.add(v)
        for num in (5, 6, 7):  # 1.25x, 1.5x, 1.75x of a power of two
            v = p * num // 4
            if threshold <= v <= max_kib:
                probes.add(v)
        p *= 2
    return sorted(probes - set(measured))


def run_sweep(ladder, key, runs, bytes_per_run, margin, verbose=True):
    pool_size = max(ladder) * KB
    pool = bytes(bytearray(range(251)) * (pool_size // 251 + 2))[:pool_size]

    def take(kib, n_runs):
        return sample(kib, key, n_runs, bytes_per_run, pool)

    results = []
    if verbose:
        print(f"{'KiB':>7} {'single':>10} {'AUTO':>10} {'ratio':>8}")
        print("-" * 38)
    for kib in ladder:
        r = take(kib, runs)
        results.append(r)
        if verbose:
            tag = "" if r["ratio"] >= margin else "  slower"
            print(f"{kib:>7} {r['single']:>10.0f} {r['auto']:>10.0f} {r['ratio']:>7.2f}x{tag}")

    # Refine the candidate until it stops moving, alternating two corrections:
    #   1. probe adversarial sizes above it, in case the ladder missed a dip (too low), and
    #   2. re-measure the point that forces it up, in case that point was just noise (too high).
    confirmed = set()
    for _ in range(8):
        changed = False

        thr = threshold_from(results, margin)
        if thr is not None:
            probes = adversarial_probes(thr, max(ladder), {r["kib"] for r in results})
            if probes:
                if verbose:
                    print(f"\nverifying {thr} KiB: probing {len(probes)} sizes that are usually worst ...")
                for kib in probes:
                    r = take(kib, runs)
                    results.append(r)
                    if verbose and r["ratio"] < margin:
                        print(f"  {kib:>5} KiB {r['ratio']:.2f}x  <- disproves {thr} KiB")
                results.sort(key=lambda r: r["kib"])
                changed = True

        thr = threshold_from(results, margin)
        blocker = blocker_below(results, thr, margin)
        if blocker is not None and blocker["kib"] not in confirmed:
            confirmed.add(blocker["kib"])
            if verbose:
                print(f"\nre-measuring {blocker['kib']} KiB ({blocker['ratio']:.2f}x) with {runs * 3} runs ...")
            again = take(blocker["kib"], runs * 3)
            idx = next(i for i, r in enumerate(results) if r["kib"] == blocker["kib"])
            results[idx] = again
            if verbose:
                print(f"  {blocker['ratio']:.2f}x -> {again['ratio']:.2f}x")
            changed = True

        if not changed:
            break

    return results


def recommend(results, margin):
    thr = threshold_from(results, margin)
    by_size = {r["kib"]: r for r in results}
    lines = []
    if thr is None:
        lines.append("No threshold found: multi-threaded blake3 never wins consistently on this machine.")
        lines.append("Keep using single-threaded blake3.")
        return None, lines

    at = by_size[thr]["ratio"]
    worst = min((r["ratio"] for r in results if r["kib"] >= thr), default=1.0)
    lines.append(f"Recommended threshold: {thr} KiB  ({thr * KB} bytes)")
    lines.append(f"  at the threshold      : {at:.2f}x")
    lines.append(f"  worst case above it   : {worst:.2f}x")
    biggest = max(results, key=lambda r: r["kib"])
    lines.append(f"  at {biggest['kib']} KiB            : {biggest['ratio']:.2f}x")
    lines.append("")
    if thr == BORG_DEFAULT_THRESHOLD_KIB:
        lines.append(f"That is borg's default ({BORG_DEFAULT_THRESHOLD_KIB} KiB), so nothing to change.")
    else:
        lines.append(f"Tell borg about it (its default is {BORG_DEFAULT_THRESHOLD_KIB} KiB):")
        lines.append("")
        lines.append(f"    export BORG_BLAKE3_MT_THRESHOLD={thr}")
    lines.append("")
    lines.append("Only repositories using --id-hash blake3 are affected.")
    return thr, lines


# Colours for a stand-alone .svg, which cannot inherit anything from a host page.
# The HTML page instead passes CSS variables so the chart follows the page theme.
PALETTE_LIGHT = {
    "fg": "#14140f",
    "mut": "#6b6a63",
    "line": "#e1e0d9",
    "win": "#2a78d6",
    "loss": "#d03b3b",
    "bg": "#ffffff",
}
PALETTE_VARS = {
    "fg": "var(--fg)",
    "mut": "var(--mut)",
    "line": "var(--line)",
    "win": "var(--win)",
    "loss": "var(--loss)",
    "bg": "none",
}


def svg_chart(results, threshold, margin, palette, title=None, subtitle=None, standalone=False, width=1120):
    """Build the bar chart as SVG markup.

    Every measured point gets a bar; only ~14 of them get a tick label, so the axis stays
    readable no matter how many sizes were measured. Used both inline in the HTML report and
    as a stand-alone .svg file.
    """
    results = sorted(results, key=lambda r: r["kib"])
    ratios = [r["ratio"] for r in results]
    lo = min(0.5, min(ratios) * 0.85)
    hi = max(2.0, max(ratios) * 1.1)
    head = 0 if not (title or subtitle) else (26 if not subtitle else 46)
    W, H = width, 460 + head
    L, R, T, B = 64, 24, 28 + head, 64
    pw, ph = W - L - R, H - T - B

    def y_of(v):
        f = (math.log(v) - math.log(lo)) / (math.log(hi) - math.log(lo))
        return T + ph - f * ph

    n = len(results)
    slot = pw / n
    bw = max(2.0, slot * 0.7)

    bars, labels = [], []
    for i, r in enumerate(results):
        x = L + i * slot + (slot - bw) / 2
        y = y_of(max(r["ratio"], lo))
        cls = "win" if r["ratio"] >= margin else "loss"
        bars.append(
            f'<rect class="{cls}" x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{(y_of(lo) - y):.1f}" rx="2">'
            f'<title>{r["kib"]} KiB: {r["ratio"]:.2f}x  ({r["single"]:.0f} -> {r["auto"]:.0f} MiB/s)</title></rect>'
        )
        # every bar is drawn, but label at most ~14 of them so ticks never collide
        if i % max(1, -(-n // 14)) == 0:
            labels.append(
                f'<text class="tick" x="{x + bw / 2:.1f}" y="{H - B + 16}" '
                f'transform="rotate(-45 {x + bw / 2:.1f} {H - B + 16})">{r["kib"]}</text>'
            )

    gridlines = []
    for v in (0.25, 0.5, 1, 2, 4, 8):
        if lo <= v <= hi:
            y = y_of(v)
            emph = ' class="base"' if v == 1 else ' class="grid"'
            gridlines.append(f'<line{emph} x1="{L}" y1="{y:.1f}" x2="{W - R}" y2="{y:.1f}"/>')
            gridlines.append(f'<text class="tick" x="{L - 10}" y="{y + 4:.1f}" text-anchor="end">{v}x</text>')

    marker = ""
    if threshold is not None:
        idx = next((i for i, r in enumerate(results) if r["kib"] == threshold), None)
        if idx is not None:
            x = L + idx * slot + slot / 2
            marker = (
                f'<line class="thr" x1="{x:.1f}" y1="{T}" x2="{x:.1f}" y2="{H - B}"/>'
                f'<text class="thrlabel" x="{x + 6:.1f}" y="{T + 12}">threshold {threshold} KiB</text>'
            )

    thr_txt = f"{threshold} KiB" if threshold is not None else "none"
    heading = ""
    if title:
        heading += f'<text class="h1" x="{L}" y="20">{title}</text>'
    if subtitle:
        heading += f'<text class="sub" x="{L}" y="40">{subtitle}</text>'

    style = (
        f'<style>rect.win{{fill:{palette["win"]}}} rect.loss{{fill:{palette["loss"]}}} '
        f'line.grid{{stroke:{palette["line"]};stroke-width:1}} '
        f'line.base{{stroke:{palette["mut"]};stroke-width:1;stroke-dasharray:4 4}} '
        f'line.thr{{stroke:{palette["fg"]};stroke-width:1;stroke-dasharray:2 3}} '
        f'text{{font:11px -apple-system,system-ui,sans-serif;fill:{palette["mut"]}}} '
        f'text.tick{{text-anchor:middle}} text.thrlabel{{fill:{palette["fg"]}}} '
        f'text.h1{{font-size:16px;fill:{palette["fg"]}}} text.sub{{font-size:12px}}</style>'
    )
    bg = f'<rect x="0" y="0" width="{W}" height="{H}" fill="{palette["bg"]}"/>' if palette["bg"] != "none" else ""
    opening = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img"'
        if standalone
        else f'<svg viewBox="0 0 {W} {H}" width="100%" role="img"'
    )
    return (
        f'{opening} aria-label="blake3 AUTO speedup by input size; recommended threshold {thr_txt}">'
        f"{style}{bg}{heading}\n"
        + "\n".join(gridlines)
        + "\n"
        + "\n".join(bars)
        + f"\n{marker}\n"
        + "\n".join(labels)
        + f'\n<text x="{L + pw / 2}" y="{H - 6}" class="tick">input size (KiB)</text>\n</svg>'
    )


def render_html(results, info, threshold, margin, path):
    results = sorted(results, key=lambda r: r["kib"])
    rows = "\n".join(
        f"<tr><td>{r['kib']}</td><td>{r['single']:.0f}</td><td>{r['auto']:.0f}</td>"
        f"<td class='{'win' if r['ratio'] >= margin else 'loss'}'>{r['ratio']:.2f}x</td></tr>"
        for r in results
    )
    thr_txt = f"{threshold} KiB" if threshold is not None else "none - MT never wins consistently"
    chart = svg_chart(results, threshold, margin, PALETTE_VARS)

    html = f"""<!doctype html>
<meta charset="utf-8"><title>blake3 multi-threading threshold</title>
<style>
 :root {{ color-scheme: light dark; --fg:#14140f; --mut:#6b6a63; --line:#e1e0d9;
          --win:#2a78d6; --loss:#d03b3b; --bg:#fff; }}
 @media (prefers-color-scheme: dark) {{
   :root {{ --fg:#f2f1ea; --mut:#9a998f; --line:#33332f; --win:#3987e5; --loss:#e05a5a; --bg:#171715; }}
 }}
 body {{ font: 15px/1.6 -apple-system, system-ui, sans-serif; color: var(--fg); background: var(--bg);
         margin: 0 auto; padding: 32px; max-width: 1180px; }}
 h1 {{ font-size: 20px; font-weight: 500; margin: 0 0 4px; }}
 p.sub {{ color: var(--mut); margin: 0 0 24px; }}
 table {{ border-collapse: collapse; font-size: 13px; margin-top: 28px; }}
 th, td {{ padding: 3px 14px 3px 0; text-align: right; border-bottom: 1px solid var(--line); }}
 th {{ color: var(--mut); font-weight: 500; }}
 td.win {{ color: var(--win); }} td.loss {{ color: var(--loss); }}
 .key {{ color: var(--mut); font-size: 13px; }}
 .key b {{ font-weight: 500; color: var(--fg); }}
</style>
<h1>blake3 <code>max_threads=AUTO</code> vs single-threaded</h1>
<p class="sub">{info['processor']} &middot; {info['cpus_available']} cores available &middot;
 {info['platform']} &middot; blake3 {info['blake3']}</p>
<p class="key">Recommended threshold: <b>{thr_txt}</b> &nbsp;|&nbsp;
 blue = AUTO faster, red = AUTO slower, dashed line = break-even. Hover a bar for details.</p>
{chart}
<table>
<tr><th>KiB</th><th>single MiB/s</th><th>AUTO MiB/s</th><th>ratio</th></tr>
{rows}
</table>
"""
    with open(path, "w") as fd:
        fd.write(html)
    return path


def main():
    ap = argparse.ArgumentParser(
        description="Find the input size above which multi-threaded blake3 pays off on this machine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--quick", action="store_true", help="15 sizes, a few seconds (rough)")
    ap.add_argument("--thorough", action="store_true", help="16 KiB steps up to 2 MiB, several minutes")
    ap.add_argument("--runs", type=int, default=5, help="timed repetitions per point (default: 5)")
    ap.add_argument("--mib-per-run", type=int, default=96, help="MiB hashed per timed run (default: 96)")
    ap.add_argument(
        "--margin",
        type=float,
        default=1.0,
        help="required speedup above the threshold; 1.0 = never slower, 1.2 = at least 20%% faster",
    )
    ap.add_argument("--html", nargs="?", const="", metavar="PATH", help="write an HTML chart (default: a temp file)")
    ap.add_argument("--open", action="store_true", help="open the HTML chart in a browser (implies --html)")
    ap.add_argument("--svg", metavar="PATH", help="write the chart as a stand-alone .svg (for docs, issues, ...)")
    ap.add_argument("--svg-title", metavar="TEXT", help="title drawn inside the .svg")
    ap.add_argument("--json", metavar="PATH", help="also write the raw measurements as JSON")
    ap.add_argument("--from-json", metavar="PATH", help="re-render from an earlier --json run instead of measuring")
    args = ap.parse_args()

    if args.from_json:
        with open(args.from_json) as fd:
            saved = json.load(fd)
        results, info = saved["results"], saved["machine"]
        margin = saved.get("margin", args.margin)
        threshold, lines = recommend(results, margin)
        for line in lines:
            print(line)
        if args.svg:
            sub = f"{info['processor']} - {info['cpus_available']} cores - blake3 {info['blake3']}"
            svg = svg_chart(results, threshold, margin, PALETTE_LIGHT, args.svg_title, sub, standalone=True)
            with open(args.svg, "w") as fd:
                fd.write(svg)
            print(f"chart -> {args.svg}")
        if args.html is not None or args.open:
            path = args.html or os.path.join(tempfile.gettempdir(), "blake3-mt-threshold.html")
            render_html(results, info, threshold, margin, path)
            print(f"chart -> {path}")
            if args.open:
                webbrowser.open("file://" + os.path.abspath(path))
        return

    ladder = LADDERS["quick"] if args.quick else LADDERS["thorough"] if args.thorough else LADDERS["balanced"]
    info = machine_info()

    print(f"{info['processor']}, {info['cpus_available']} cores available (of {info['cpus_total']})")
    print(f"{info['platform']}, python {info['python']}, blake3 {info['blake3']}")
    print(f"{len(ladder)} sizes, {args.runs} runs each, ~{args.mib_per_run} MiB per run\n")
    if info["cpus_available"] < 2:
        print("Only one core available - multi-threaded blake3 cannot help here.\n")

    key = b"\x00" * 32  # keyed blake3, same as borg's id_hash
    t0 = time.monotonic()
    results = run_sweep(ladder, key, args.runs, args.mib_per_run * MB, args.margin)
    elapsed = time.monotonic() - t0

    threshold, lines = recommend(results, args.margin)
    print("\n" + "=" * 60)
    for line in lines:
        print(line)
    print("=" * 60)
    print(f"\nmeasured in {elapsed:.0f}s. Note the speedup is not monotonic: it peaks at powers of two,")
    print("so a size just below a power of two is a local worst case.")

    if args.json:
        with open(args.json, "w") as fd:
            json.dump(
                {"machine": info, "margin": args.margin, "threshold_kib": threshold, "results": results}, fd, indent=1
            )
        print(f"raw measurements -> {args.json}")

    if args.svg:
        sub = f"{info['processor']} - {info['cpus_available']} cores - blake3 {info['blake3']}"
        with open(args.svg, "w") as fd:
            fd.write(svg_chart(results, threshold, args.margin, PALETTE_LIGHT, args.svg_title, sub, standalone=True))
        print(f"chart -> {args.svg}")

    if args.html is not None or args.open:
        path = args.html or os.path.join(tempfile.gettempdir(), "blake3-mt-threshold.html")
        render_html(results, info, threshold, args.margin, path)
        print(f"chart -> {path}")
        if args.open:
            webbrowser.open("file://" + os.path.abspath(path))


if __name__ == "__main__":
    main()
