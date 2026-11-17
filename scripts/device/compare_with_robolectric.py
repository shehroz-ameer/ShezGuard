#!/usr/bin/env python3
"""Compares the tagged lines of one emulator run with the Robolectric run of the same shared tests.

Usage: compare_with_robolectric.py <robolectric-junit-xml-dir> <device tagged.txt (or logcat.txt)> <api>

Only tags printed by src/sharedTest classes are compared: [103], [111], [117] (differential test,
JVM default SDK 34, lines carry no sdk=), [N4] (step 14 phase 2), [N6], [N7s] and [baseline]
(lines carry sdk=N). For each tag:
- "same": the device printed exactly the Robolectric lines for that SDK;
- "DIFFERS": both ran and the lines differ (both sides printed);
- "no Robolectric run at this SDK": nothing to compare against (device lines are listed).
For lines without sdk=, the Robolectric side is SDK 34; on another API a difference is an API-level
difference, not a contradiction of a Robolectric result, and is labelled that way.

Counts ("... ran Nx", any tag): a device line whose text, without sdk= and the count, matches a
Robolectric line must have the same count as Robolectric at the same SDK, or, when Robolectric did not
run that SDK, the same count as every Robolectric SDK. Any difference is "COUNT DIFFERS" and fails the
comparison (step 14 follow-up: a count of 0 is how a test that never reached the hostile code shows up).
Device count lines with no Robolectric counterpart (device-only tests, e.g. [N7d]) are listed.

Exit code 1 if any tag DIFFERS at the same SDK or any count differs. Python 3.9+, standard library only.
"""
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TAGS = ["103", "111", "117", "N4", "N6", "N7s", "baseline"]
COUNT = re.compile(r"\bran (\d+)x")
JVM_DEFAULT_SDK = "34"


def extract(src: str, sdk=None):
    out = subprocess.run([sys.executable, "-I", str(HERE / "extract_tagged.py"), src] + (["--sdk", sdk] if sdk else []),
                         check=True, stdout=subprocess.PIPE, text=True).stdout
    return [l for l in out.splitlines() if l]


def by_tag(lines):
    d = {t: [] for t in TAGS}
    for l in lines:
        m = re.match(r"\[([^\]]+)\]", l)
        if m and m.group(1) in d:
            d[m.group(1)].append(l)
    return d


def main() -> int:
    rob_dir, logcat, api = sys.argv[1], sys.argv[2], sys.argv[3]
    dev = by_tag(extract(logcat, api))
    rob = by_tag(extract(rob_dir, api))
    contradiction = False
    for t in TAGS:
        d, r = dev[t], rob[t]
        has_sdk = any("sdk=" in l for l in d + r)
        rob_sdk = api if has_sdk else JVM_DEFAULT_SDK
        if not d and not r:
            print(f"[{t}] not printed on either side at API {api}")
            continue
        if not r:
            print(f"[{t}] no Robolectric run at SDK {api}; device printed {len(d)} line(s):")
            for l in d:
                print(f"    device: {l}")
            continue
        if not d:
            print(f"[{t}] Robolectric SDK {rob_sdk} printed {len(r)} line(s), device API {api} printed none")
            continue
        if d == r:
            print(f"[{t}] same ({len(d)} lines; device API {api} vs Robolectric SDK {rob_sdk})")
            continue
        same_sdk = rob_sdk == api
        contradiction |= same_sdk
        label = "DIFFERS at the same SDK" if same_sdk else f"differs (device API {api} vs Robolectric SDK {rob_sdk}: API-level difference)"
        print(f"[{t}] {label}")
        for l in sorted(set(r) - set(d)):
            print(f"    robolectric only: {l}")
        for l in sorted(set(d) - set(r)):
            print(f"    device only:      {l}")
    contradiction |= compare_counts(extract(rob_dir), extract(logcat, api), api)
    return 1 if contradiction else 0


def count_key(line: str):
    """(text without sdk= and count, sdk or None, count) for a line carrying "ran Nx", else None."""
    m = COUNT.search(line)
    if not m:
        return None
    sdk = re.search(r"\bsdk=(\d+)", line)
    key = COUNT.sub("ran ?x", re.sub(r"\bsdk=\d+ ", "", line))
    return key, (sdk.group(1) if sdk else None), int(m.group(1))


def compare_counts(rob_lines, dev_lines, api: str) -> bool:
    rob = {}
    for l in rob_lines:
        k = count_key(l)
        if k:
            rob.setdefault(k[0], {})[k[1]] = k[2]
    failed = False
    print(f"counts (device API {api}):")
    for l in dev_lines:
        k = count_key(l)
        if not k:
            continue
        key, _, n = k
        if key not in rob:
            print(f"    no Robolectric counterpart: {l}")
            continue
        per_sdk = rob[key]
        expected = {per_sdk[api]} if api in per_sdk else set(per_sdk.values())
        if n in expected and len(expected) == 1:
            where = f"SDK {api}" if api in per_sdk else "all Robolectric SDKs " + ",".join(sorted(per_sdk))
            print(f"    same ({n}x, Robolectric {where}): {key}")
        else:
            failed = True
            print(f"    COUNT DIFFERS: device {n}x, Robolectric {per_sdk}: {key}")
    return failed


if __name__ == "__main__":
    sys.exit(main())
