#!/usr/bin/env python3
"""Benchmark every chunker scan kernel of a borg build and print a chunkers x kernels table.

borg picks a default scan kernel per platform (the *_kernel_default() functions of
the C kernels); BORG_FASTCDC_KERNEL / BORG_BUZHASH64_KERNEL / BORG_AES_CHUNKER_KERNEL
name another one. Which kernel is fastest is not predictable from the instruction set
- NEON beats the sequential loop on an Apple M3, while on a Zen 4 the sequential loop
beats AVX-512 - so the only way to know is to measure on the machine in question.
That is what this does.

It drives `borg benchmark cpu --chunking --json` once per kernel combination, so it
needs nothing but a `borg` binary in $PATH (or --borg PATH) and python3. It works on
arm64 and x86-64, on Linux, the BSDs and macOS; which kernels exist is discovered
from the binary, not assumed.

Usage:

    scripts/bench_chunker_kernels.py                 # 3 repetitions, ~1 GiB per row
    scripts/bench_chunker_kernels.py --reps 5
    scripts/bench_chunker_kernels.py --smoke         # tiny data, just checks it works
    scripts/bench_chunker_kernels.py --json out.json # keep the raw samples too

Note on the data: `borg benchmark cpu` makes its own random buffer per process, so
every run chunks different (but equally random, equally large) bytes. Repetitions and
the median column absorb that; the reported spread says how much it mattered.
"""

import argparse
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

# Which env var selects the scan kernel of which chunker. A chunker that is in no
# group has no kernel to select and is reported in the "n/a" column.
KERNEL_ENVS = [
    ("BORG_FASTCDC_KERNEL", ["fastcdc"]),
    ("BORG_BUZHASH64_KERNEL", ["buzhash64"]),
    ("BORG_AES_CHUNKER_KERNEL", ["toeplitz-aes", "rabin-aes", "goldilocks-aes"]),
]

NO_KERNEL = "n/a"  # column for chunkers that have no selectable kernel

# borg reports its kernels most-specialised first ("avx512,avx2,blockwise,scalar");
# reversed, the table reads left to right from the simplest kernel to the fanciest.
VALID_VALUES_RE = re.compile(r"Valid values:\s*(\S.*?)\s*$", re.MULTILINE)

# Keeps a probe run to 128 KiB and one iteration per row: enough to construct every
# chunker (which is what validates a kernel request) without benchmarking anything.
PROBE_ENV = {"_BORG_BENCHMARK_CPU_TEST": "1"}


def log(msg):
    """Progress goes to stderr, so that stdout stays a clean table."""
    print(msg, file=sys.stderr, flush=True)


def cpu_model():
    """A human-readable CPU name, or the bare architecture if nothing better is found."""
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True)
            return out.strip()
        if system == "Linux":
            with open("/proc/cpuinfo") as f:
                for line in f:
                    # x86 says "model name", arm64 often only has "Model"/"CPU part"
                    if line.split(":")[0].strip() in ("model name", "Model"):
                        return line.split(":", 1)[1].strip()
        else:  # the BSDs
            out = subprocess.check_output(["sysctl", "-n", "hw.model"], text=True)
            return out.strip()
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return platform.processor() or platform.machine()


def run_borg(borg, extra_env, smoke):
    """One `borg benchmark cpu --chunking --json` run.

    Returns (rows, error): rows is the parsed chunkers list on success, error is a
    one-line reason on failure (an unsupported kernel, a borg too old, ...).
    """
    env = dict(os.environ)
    # start from a clean slate, so that a kernel var set in the caller's shell
    # cannot silently apply to runs that mean to measure the default
    for envvar, _ in KERNEL_ENVS:
        env.pop(envvar, None)
    env.pop("_BORG_BENCHMARK_CPU_TEST", None)
    env.update(extra_env)
    if smoke:
        env.update(PROBE_ENV)
    proc = subprocess.run(
        [borg, "benchmark", "cpu", "--chunking", "--json"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = proc.stdout + proc.stderr
    if proc.returncode != 0:
        return None, error_line(output, proc.returncode)
    try:
        # tolerate anything borg may print around the JSON document
        start = proc.stdout.index("{")
        doc, _ = json.JSONDecoder().raw_decode(proc.stdout[start:])
        rows = doc["chunkers"]
    except (ValueError, KeyError) as e:
        return None, "could not parse the --json output (%s)" % e
    # a chunker that could not be constructed (e.g. an unusable kernel was
    # requested) is reported as an error row, with the benchmark going on
    for row in rows:
        if "error" in row:
            return None, row["error"]
    return rows, None


def error_line(output, returncode):
    """The most informative single line of a failed run."""
    for line in output.splitlines():
        # "Error:" alone is just the header borg prints above the real message
        if "ValueError:" in line or ("Error:" in line and line.strip() != "Error:"):
            return line.strip()
    return "borg exited with rc=%d" % returncode


def discover_kernels(borg, envvar):
    """The kernels of <envvar> that this build has AND this CPU can run.

    The build's list comes from borg itself: an impossible value makes it name the
    valid ones. Each is then probed, because a kernel can be compiled in and still
    be unusable here (an AVX-512 binary on a CPU without it), and a kernel that
    cannot run must not enter the plan - borg refuses rather than falling back, so
    it would take an entire run down with it.
    """
    _, err = run_borg(borg, {envvar: "!invalid!"}, smoke=True)
    if err is None:
        log("  %s: this borg does not reject an invalid kernel - skipping" % envvar)
        return []
    match = VALID_VALUES_RE.search(err)
    if not match:
        log("  %s: not supported by this borg (%s)" % (envvar, err))
        return []
    names = [n.strip() for n in match.group(1).split(",") if n.strip()]
    usable = []
    for name in reversed(names):  # simplest kernel first, see VALID_VALUES_RE
        _, err = run_borg(borg, {envvar: name}, smoke=True)
        if err is None:
            usable.append(name)
        else:
            log("  %s=%s: unusable here (%s)" % (envvar, name, err))
    log("  %s: %s" % (envvar, ", ".join(usable) if usable else "none usable"))
    return usable


def build_plan(kernel_sets):
    """The runs of one repetition, as a list of {envvar: kernel} dicts.

    The env vars are independent, so a single run measures one kernel of each of
    them at once: as many runs as the longest kernel list, with the shorter lists
    cycling. Every kernel is measured at least once per repetition.
    """
    n_runs = max((len(ks) for ks in kernel_sets.values()), default=0)
    plan = []
    for i in range(n_runs):
        plan.append({envvar: ks[i % len(ks)] for envvar, ks in kernel_sets.items() if ks})
    return plan


def kernel_of(algo, env_of_algo, run_env):
    """Which kernel produced this chunker's row in this run."""
    envvar = env_of_algo.get(algo)
    return run_env.get(envvar, NO_KERNEL) if envvar else NO_KERNEL


def render(rows, columns, samples):
    """The chunkers x kernels table, throughput only."""
    label_w = max(len(r) for r in rows)
    cells = {}
    for row in rows:
        for col in columns:
            values = samples.get((row, col))
            cells[(row, col)] = "%.1f" % statistics.median(values) if values else "-"
    widths = [max([len(col)] + [len(cells[(row, col)]) for row in rows]) for col in columns]

    out = []
    header = " " * label_w + " |" + "|".join(" %*s " % (w, c) for w, c in zip(widths, columns))
    out.append(header)
    out.append("-" * (label_w + 1) + "+" + "+".join("-" * (w + 2) for w in widths))
    for row in rows:
        line = "%-*s |" % (label_w, row)
        line += "|".join(" %*s " % (w, cells[(row, col)]) for w, col in zip(widths, columns))
        out.append(line)
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark all chunker scan kernels of a borg build (throughput in MB/s).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--borg", default=None, help="borg binary to drive (default: borg from $PATH)")
    parser.add_argument("--reps", type=int, default=3, help="repetitions of the whole matrix (default: 3)")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="run on minimal data - checks that the matrix works, the numbers are meaningless",
    )
    parser.add_argument("--json", metavar="FILE", help="also write the raw samples (MB/s per run) there")
    parser.add_argument(
        "--warmup",
        type=int,
        default=1,
        help="discarded runs before measuring, to let the CPU clock ramp up (default: 1)",
    )
    args = parser.parse_args()

    borg = args.borg or shutil.which("borg")
    if not borg:
        log("no borg binary in $PATH - pass --borg PATH")
        return 2
    try:
        version = subprocess.check_output([borg, "--version"], text=True).strip()
    except (OSError, subprocess.SubprocessError) as e:
        log("cannot run %s: %s" % (borg, e))
        return 2

    log("borg: %s (%s)" % (version, borg))
    log("discovering kernels ...")
    kernel_sets = {envvar: discover_kernels(borg, envvar) for envvar, _ in KERNEL_ENVS}
    plan = build_plan(kernel_sets)
    if not plan:
        log("no selectable kernels at all - nothing to compare")
        return 1

    env_of_algo = {algo: envvar for envvar, algos in KERNEL_ENVS for algo in algos}
    samples = {}  # (row label, kernel) -> [MB/s, ...]
    row_order = []  # chunker labels, in the order the benchmark reports them
    started = time.time()
    total = len(plan) * args.reps
    done = 0

    # A cold CPU is a slow CPU: the first runs of a session come out low while the
    # clock ramps up, which skews whichever kernel happened to go first.
    for i in range(args.warmup):
        log("[warmup %d/%d]" % (i + 1, args.warmup))
        run_borg(borg, plan[0], args.smoke)

    for rep in range(1, args.reps + 1):
        for run_env in plan:
            done += 1
            what = " ".join("%s=%s" % (k.split("_", 1)[1], v) for k, v in sorted(run_env.items()))
            log("[%d/%d] %s" % (done, total, what))
            rows, err = run_borg(borg, run_env, args.smoke)
            if err:
                log("        failed: %s" % err)
                continue
            for row in rows:
                algo = row["algo"]
                label = "%s,%s" % (algo, row["algo_params"]) if row.get("algo_params") else algo
                if label not in row_order:
                    row_order.append(label)
                mbs = row["size"] / row["time"] / 1e6
                samples.setdefault((label, kernel_of(algo, env_of_algo, run_env)), []).append(mbs)

    if not samples:
        log("every run failed - no results")
        return 1

    # Columns in env var order, simplest kernel first, kernel-less chunkers last.
    # Different env vars share kernel names (fastcdc and buzhash64 both have
    # 'scalar'), and one column per name is enough: the rows keep them apart.
    columns = []
    for envvar, _ in KERNEL_ENVS:
        columns.extend(k for k in kernel_sets[envvar] if k not in columns)
    if any(col == NO_KERNEL for _, col in samples):
        columns.append(NO_KERNEL)

    title = "%s (%s, %s)" % (cpu_model(), platform.machine(), platform.system())
    print(title)
    print(
        "%s, median of %d repetitions, MB/s%s"
        % (version, args.reps, " [SMOKE - not real numbers]" if args.smoke else "")
    )
    print()
    print(render(row_order, columns, samples))

    spreads = [((max(v) - min(v)) / max(v), key) for key, v in samples.items() if len(v) > 1 and max(v) > 0]
    if spreads:
        worst, (row, col) = max(spreads)
        print()
        print(
            "run-to-run spread: %.1f%% median, %.1f%% worst (%s / %s)"
            % (100 * statistics.median(s for s, _ in spreads), 100 * worst, row, col)
        )
    log("total time: %.0fs" % (time.time() - started))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(
                {
                    "cpu": title,
                    "borg": version,
                    "reps": args.reps,
                    "smoke": args.smoke,
                    "samples_mbs": {"%s|%s" % key: values for key, values in samples.items()},
                },
                f,
                indent=1,
                sort_keys=True,
            )
        log("raw samples: %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
