#!/usr/bin/env python3
"""Hand-written mutation checks for ShezGuard (see README.md in this directory).

Usage, from anywhere inside the repository:
    python3 scripts/mutation/run_mutants.py scripts/mutation/step10_activity_guard.py
    python3 scripts/mutation/run_mutants.py scripts/mutation/step10_activity_guard.py --only a1,e

For each mutant: apply its exact text edits to one source file, run the selected unit tests, record
which tests failed, and restore the original bytes. Restoration happens in a `finally` block after
every mutant, and the file's SHA-256 is verified at the end. Python 3.9+, standard library only.
"""
import argparse
import hashlib
import importlib.util
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MODULE = "shezguard-core"


def load(definitions: Path):
    spec = importlib.util.spec_from_file_location("mutants", definitions)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def apply(text: str, mutant: dict) -> str:
    for old, new in mutant["edits"]:
        count = text.count(old)
        if count != 1:
            raise SystemExit(f"mutant {mutant['id']}: anchor occurs {count} times, expected 1:\n{old}")
        text = text.replace(old, new)
    return text


def run_tests(tests, variant: str):
    """Runs the selected tests; returns (ran, {test name without [sdk]: failed count}, gradle exit)."""
    results = REPO / MODULE / "build" / "test-results" / f"test{variant}UnitTest"
    shutil.rmtree(results, ignore_errors=True)
    cmd = ["./gradlew", f":{MODULE}:test{variant}UnitTest", "-q"]
    for t in tests:
        cmd += ["--tests", t if t.endswith("*") else t + "*"]  # '*' also matches Robolectric's name[sdk]
    proc = subprocess.run(cmd, cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ran, failed = 0, {}
    for xml in results.glob("*.xml"):
        for case in ET.parse(xml).getroot().iter("testcase"):
            ran += 1
            if case.find("failure") is not None or case.find("error") is not None:
                name = case.get("classname").rsplit(".", 1)[-1] + "." + re.sub(r"\[\d+\]$", "", case.get("name"))
                failed[name] = failed.get(name, 0) + 1
    return ran, failed, proc.returncode, proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("definitions", type=Path)
    ap.add_argument("--only", help="comma-separated mutant ids")
    ap.add_argument("--variant", default="Debug", choices=["Debug", "Release"])
    args = ap.parse_args()

    mod = load(args.definitions.resolve())
    target = REPO / mod.FILE
    original = target.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    backup = REPO / MODULE / "build" / "mutation" / (target.name + ".orig")
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(original)
    print(f"target {mod.FILE}\nsha256 {digest}\nbackup {backup.relative_to(REPO)}\n")

    ran, failed, code, out = run_tests(mod.TESTS, args.variant)
    if code != 0 or failed or ran == 0:
        print(out[-3000:])
        raise SystemExit(f"baseline is not green (ran={ran}, failed={failed}); refusing to run mutants")
    print(f"baseline: {ran} test cases, all passing\n")

    wanted = set(args.only.split(",")) if args.only else None
    rows = []
    try:
        for m in mod.MUTANTS:
            if wanted and m["id"] not in wanted:
                continue
            try:
                target.write_text(apply(original.decode("utf-8"), m), encoding="utf-8")
                ran, failed, code, out = run_tests(mod.TESTS, args.variant)
            finally:
                target.write_bytes(original)
            if ran == 0:
                verdict = "BUILD ERROR (no tests ran; not counted as caught)"
                print(out[-2000:])
            elif failed:
                verdict = "caught"
            else:
                verdict = "SURVIVED"
            rows.append((m["id"], m["description"], verdict, ran, failed))
            print(f"[{m['id']}] {verdict}  ({ran} test cases ran)")
            for name, n in sorted(failed.items()):
                print(f"      {name}  ({n} failed)")
    finally:
        target.write_bytes(original)
        restored = hashlib.sha256(target.read_bytes()).hexdigest() == digest
        print(f"\nrestored byte for byte: {restored}")
        if not restored:
            print(f"RESTORE FAILED: copy {backup} back to {target}", file=sys.stderr)
            return 2

    print("\n| Mutant | Change | Result | Caught by |\n|---|---|---|---|")
    for mid, desc, verdict, ran, failed in rows:
        by = ", ".join(f"`{n}` ({c})" for n, c in sorted(failed.items())) or "none"
        print(f"| {mid} | {desc} | {verdict} | {by} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
