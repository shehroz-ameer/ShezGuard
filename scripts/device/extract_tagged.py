#!/usr/bin/env python3
"""Extracts the tagged characterisation lines ("[111] ...", "[N6] ...", "[H1] ...", "[baseline] ...") that the
shared tests print, from JUnit XML (Robolectric <system-out>), from a logcat dump (device runs, tag
System.out), or from a tagged.txt this script wrote earlier (device runs keep only that file since the
step 14 secret-scan follow-up). Prints them sorted and de-duplicated, one per line, so two runs can be compared with diff.

Usage: extract_tagged.py <junit-xml-dir | logcat.txt | tagged.txt> [--sdk N]
  --sdk N keeps only lines for SDK N: lines that carry "sdk=N", plus lines with no sdk= field
  (the differential tests run at Robolectric's default SDK, 34, on the JVM).
Python 3.9+, standard library only.
"""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

TAG = re.compile(r"(\[(?:\d+|N\d+[a-z]?|H\d+|baseline)\] .*)$")


def lines_from(path: Path):
    if path.is_dir():
        for xml in sorted(path.glob("*.xml")):
            for node in ET.parse(xml).getroot().iter("system-out"):
                yield from (node.text or "").splitlines()
    else:
        # logcat: only what the tests printed (println goes to tag System.out); other apps log "[123] ..." too.
        # A tagged.txt line starts with the tag itself (a logcat line starts with a date).
        yield from (l for l in path.read_text(errors="replace").splitlines() if " System.out: " in l or l.startswith("["))


def main() -> int:
    args = sys.argv[1:]
    sdk = None
    if "--sdk" in args:
        i = args.index("--sdk")
        sdk = args[i + 1]
        del args[i:i + 2]
    out = set()
    for line in lines_from(Path(args[0])):
        m = TAG.search(line)
        if not m:
            continue
        text = m.group(1).rstrip()
        found = re.search(r"\bsdk=(\d+)", text)
        if sdk is not None and found and found.group(1) != sdk:
            continue
        out.add(text)
    print("\n".join(sorted(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
