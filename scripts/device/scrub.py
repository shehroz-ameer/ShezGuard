#!/usr/bin/env python3
"""Masks secrets and identifiers in a results folder before it is kept, then re-scans it.

Usage: scrub.py <folder> [--check] [--literals FILE]
  default   mask every match in place in the folder's text files, then re-scan; exit 1 if anything
            still matches (also inside .tar.gz members, which are scanned but not rewritten)
  --check   scan only, change nothing; exit 1 on any match
  --literals FILE  extra exact strings to mask, one per line (e.g. the device's ro.serialno and the
            debug certificate's fingerprints, which run scripts read at run time). Never printed.

Patterns: Google API keys (AIza...), Google OAuth access tokens (ya29.), AWS access key ids (AKIA...),
private-key PEM headers, email addresses (except the test-fixture domains in FIXTURE_DOMAINS), device serial numbers (ro.serialno / ro.boot.serialno
values and the emulator's EMULATOR...X... form), the host's adb public key, and certificate fingerprints written as colon-separated
hex (SHA-256 and SHA-1). Output names each file and pattern with a count; matched values are never
printed. Python 3.9+, standard library only.
"""
import re
import sys
import tarfile
from pathlib import Path

PATTERNS = {
    "google-api-key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "google-oauth-token": re.compile(r"ya29\.[0-9A-Za-z_\-.]+"),
    "aws-access-key-id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private-key-header": re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
    "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"),
    # Only the value (group "v") is masked; the property name stays readable.
    "serial-property": re.compile(r"(?i)(?:ro\.(?:boot\.)?serialno|\bserial(?:no|_number)?)\]?\s*[=:]\s*\[?(?P<v>[A-Za-z0-9]{6,})"),
    "emulator-serial": re.compile(r"\bEMULATOR\d+X\d+X\d+X\d+\b"),
    # The host's adb public key (base64, begins "QAAAA"), as AdbDebuggingManager logs it on connect.
    "adb-public-key": re.compile(r"QAAAA[A-Za-z0-9+/]{300,}={0,2}"),
    "cert-fingerprint-sha256": re.compile(r"\b(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}\b"),
    "cert-fingerprint-sha1": re.compile(r"\b(?:[0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}\b"),
}
TEXT_SUFFIXES = {".txt", ".xml", ".json", ".md", ".csv", ".log"}

# Not addresses: the URI test fixtures put userinfo before these hosts ("user@evil.com"), violations
# render as "CODE@uri.path", and Kotlin has "this@entryPoint.allowHosts". An "email" match whose domain
# is listed here, or ends in a reserved test TLD, is left alone; every other one is masked.
FIXTURE_DOMAINS = {"example.com", "example.org", "example.net", "evil.com", "uri.path", "uri.query",
                   "uri.host", "uri.fragment", "uri.authority", "entrypoint.allowhosts"}
FIXTURE_SUFFIXES = (".invalid", ".test", ".example", ".localhost")


def ignored(name: str, m: re.Match) -> bool:
    if name != "email":
        return False
    domain = m.group(0).rsplit("@", 1)[1].lower()
    return domain in FIXTURE_DOMAINS or domain.endswith(FIXTURE_SUFFIXES)


def literal_patterns(path):
    if not path:
        return {}
    vals = [l.strip() for l in Path(path).read_text().splitlines() if len(l.strip()) >= 6]
    return {f"literal-{i}": re.compile(re.escape(v), re.IGNORECASE) for i, v in enumerate(vals)}


def mask(name: str, m: re.Match) -> str:
    if ignored(name, m):
        return m.group(0)
    if "v" in m.re.groupindex and m.group("v") is not None:
        whole, start = m.group(0), m.start("v") - m.start(0)
        return whole[:start] + f"[MASKED:{name}]" + whole[start + len(m.group("v")):]
    return f"[MASKED:{name}]"


def scan_text(text, pats):
    counts = {n: sum(1 for m in p.finditer(text) if not ignored(n, m)) for n, p in pats.items()}
    return {n: c for n, c in counts.items() if c}


def main() -> int:
    args = sys.argv[1:]
    check = "--check" in args
    if check:
        args.remove("--check")
    lit = None
    if "--literals" in args:
        i = args.index("--literals")
        lit = args[i + 1]
        del args[i:i + 2]
    folder = Path(args[0])
    pats = {**PATTERNS, **literal_patterns(lit)}
    files = [folder] if folder.is_file() else sorted(p for p in folder.rglob("*") if p.is_file())
    masked_total = 0
    remaining = 0
    for f in files:
        if f.name.endswith(".tar.gz"):
            with tarfile.open(f) as t:
                for m in t.getmembers():
                    if m.isfile():
                        hits = scan_text(t.extractfile(m).read().decode(errors="replace"), pats)
                        for n, c in hits.items():
                            remaining += c
                            print(f"REMAINS {f}:{m.name}: {n} x{c} (archive member, not rewritten)")
            continue
        if f.suffix not in TEXT_SUFFIXES:
            continue
        text = f.read_text(errors="replace")
        hits = scan_text(text, pats)
        if not hits:
            continue
        if check:
            for n, c in hits.items():
                remaining += c
                print(f"FOUND {f}: {n} x{c}")
            continue
        for n, p in pats.items():
            text = p.sub(lambda m, n=n: mask(n, m), text)
        f.write_text(text)
        for n, c in hits.items():
            masked_total += c
            print(f"masked {f}: {n} x{c}")
        for n, c in scan_text(text, pats).items():
            remaining += c
            print(f"REMAINS {f}: {n} x{c}")
    print(f"scrub: {'checked' if check else 'masked ' + str(masked_total) + ','} {remaining} remaining in {folder}")
    return 1 if remaining else 0


if __name__ == "__main__":
    sys.exit(main())
