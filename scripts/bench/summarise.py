#!/usr/bin/env python3
"""Summarises one benchmark results folder written by scripts/bench/run_bench.sh (docs/BENCHMARK.md).

Usage: summarise.py <results folder>

Prints two Markdown tables, never mixed:
- Method A (per-call timed loop): computed from the raw per-call samples in percall_raw.tar.gz.
  Per run: median, p95, p99 (nearest rank over all samples of that run). Across runs: the range
  (min-max) of each statistic and the spread of the run medians, (max - min) / min. Also checks
  that the raw files agree with the [BENCH-PERCALL] lines printed on the device.
- Method B (androidx.benchmark): from micro_run<k>.json. Per run, the library's median and minimum
  time per iteration (each measurement is an average over a batch of iterations, so these are not
  per-call percentiles) and its median allocation count; across runs, the range.

All figures: emulator, indicative only. Python 3.9+, standard library only.
"""
import json
import math
import re
import sys
import tarfile
from pathlib import Path

ORDER = [
    "simple_link", "many_params", "max_length", "nested_depth1", "nested_depth4", "large_bundle",
    "early_block_unregistered", "early_block_scheme",
    "baseline_app_reads_link", "baseline_app_reads_bundle", "baseline_sanitizer_nested1",
]


def pct(sorted_vals, p):
    return sorted_vals[min(len(sorted_vals) - 1, max(0, math.ceil(p * len(sorted_vals)) - 1))]


def us(ns):
    return f"{ns / 1000:.1f}"


def rng(vals):
    return f"{us(min(vals))}–{us(max(vals))}"


def method_a(folder: Path):
    raw = {}
    with tarfile.open(folder / "percall_raw.tar.gz") as t:
        for m in t.getmembers():
            mm = re.search(r"run(\d+)_(.+)\.txt$", m.name)
            if not mm or not m.isfile() or Path(m.name).name.startswith("._"):
                continue
            vals = [int(x) for x in t.extractfile(m).read().decode().split()]
            raw.setdefault(mm.group(2), {})[int(mm.group(1))] = vals
    lines = {}
    for l in (folder / "percall_lines.txt").read_text().splitlines():
        kv = dict(x.split("=", 1) for x in l.split()[1:] if "=" in x)
        lines[(kv["scenario"], int(kv["run"]))] = kv
    print("Method A, per-call timed loop (µs per call; emulator, indicative only)\n")
    print("| Scenario | Outcome | Runs × calls | Median, per run (min–max) | p95, per run (min–max) | p99, per run (min–max) | Spread of run medians | GCs during timed calls, per run |")
    print("|---|---|---|---|---|---|---|---|")
    mismatches = 0
    for s in ORDER + sorted(set(raw) - set(ORDER)):
        if s not in raw:
            continue
        runs = raw[s]
        med, p95, p99, gcs = [], [], [], []
        outcome = ""
        for k, vals in sorted(runs.items()):
            sv = sorted(vals)
            med.append(pct(sv, 0.50)); p95.append(pct(sv, 0.95)); p99.append(pct(sv, 0.99))
            kv = lines.get((s, k), {})
            outcome = kv.get("outcome", outcome)
            if kv and (int(kv["median_ns"]) != med[-1] or int(kv["p95_ns"]) != p95[-1]):
                mismatches += 1
            if kv.get("gc_before", "?").isdigit() and kv.get("gc_after", "?").isdigit():
                gcs.append(int(kv["gc_after"]) - int(kv["gc_before"]))
        n = len(next(iter(runs.values())))
        spread = (max(med) - min(med)) / min(med) * 100 if min(med) else float("nan")
        gc = f"{min(gcs)}–{max(gcs)}" if gcs else "?"
        print(f"| `{s}` | {outcome} | {len(runs)} × {n} | {rng(med)} | {rng(p95)} | {rng(p99)} | {spread:.0f}% | {gc} |")
    print(f"\nRaw files vs device lines: {mismatches} mismatches.\n")


def method_b(folder: Path):
    files = sorted(folder.glob("micro_run*.json"))
    if not files:
        print("Method B: no androidx.benchmark output.\n")
        return
    per = {}
    for f in files:
        data = json.loads(f.read_text())
        for b in data["benchmarks"]:
            m = b["metrics"]
            name = re.sub(r"^EMULATOR_", "", b["name"])  # androidx.benchmark prefixes names on an emulator
            per.setdefault(name, []).append(
                (m["timeNs"]["median"], m["timeNs"]["minimum"], m.get("allocationCount", {}).get("median"),
                 b.get("repeatIterations"), len(m["timeNs"].get("runs", []))))
    print("Method B, androidx.benchmark 1.5.0 (µs per iteration, batch averages; emulator, indicative only)\n")
    print("| Scenario | Runs | Median, per run (min–max) | Minimum, per run (min–max) | Spread of run medians | Allocations per iteration (median) | Measurements × iterations |")
    print("|---|---|---|---|---|---|---|")
    for s in ORDER + sorted(set(per) - set(ORDER)):
        if s not in per:
            continue
        r = per[s]
        med = [x[0] for x in r]; mn = [x[1] for x in r]
        alloc = sorted({round(x[2]) for x in r if x[2] is not None})
        spread = (max(med) - min(med)) / min(med) * 100
        print(f"| `{s}` | {len(r)} | {rng(med)} | {rng(mn)} | {spread:.0f}% | {', '.join(map(str, alloc)) or '?'} | {r[0][4]} × {r[0][3]} |")
    print()


def main() -> int:
    folder = Path(sys.argv[1])
    dev = (folder / "device.txt").read_text() if (folder / "device.txt").exists() else ""
    if "NOT RESULTS" in dev:
        print("**SCRIPT CHECK ONLY: reduced runs and samples; these numbers are NOT RESULTS.**\n")
    print(f"Source: `{folder.name}`\n")
    method_a(folder)
    method_b(folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
