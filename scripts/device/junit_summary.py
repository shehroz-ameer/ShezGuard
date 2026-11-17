#!/usr/bin/env python3
"""Reduces JUnit XML to one line per test, so raw XML (whose <system-out> and stack traces can carry
anything the process printed) need not be kept in docs/results.

Usage: junit_summary.py <junit-xml-dir>
Output: a "tests=N failures=F skipped=S" header, then one line per test, sorted:
  PASS <class>#<name>
  SKIP <class>#<name>: <first line of the skip message>
  FAIL <class>#<name>: <first line of the failure message>
Python 3.9+, standard library only.
"""
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def first_line(node) -> str:
    text = (node.get("message") or node.text or "").strip()
    return text.splitlines()[0][:300] if text else ""


def main() -> int:
    rows, fails, skips = [], 0, 0
    for xml in sorted(Path(sys.argv[1]).glob("*.xml")):
        for tc in ET.parse(xml).getroot().iter("testcase"):
            name = f"{tc.get('classname')}#{tc.get('name')}"
            f = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
            s = tc.find("skipped")
            if f is not None:
                fails += 1
                rows.append(f"FAIL {name}: {first_line(f)}")
            elif s is not None:
                skips += 1
                rows.append(f"SKIP {name}: {first_line(s)}")
            else:
                rows.append(f"PASS {name}")
    print(f"tests={len(rows)} failures={fails} skipped={skips}")
    print("\n".join(sorted(rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
