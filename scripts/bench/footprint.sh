#!/usr/bin/env bash
# Step 14 phase 3: ShezGuard's size footprint (docs/BENCHMARK.md, "Footprint").
#
# Usage: scripts/bench/footprint.sh <run label>
# Writes docs/results/<date>_footprint_<run label>/footprint.txt (refuses to overwrite).
#
# Measures, with the SDK's own tools (build-tools 36.0.0 d8 and dexdump, cmdline-tools apkanalyzer):
# 1. The release AAR of :shezguard-core: file size and the size of each entry.
# 2. Methods: classes.jar converted to dex with d8 (--release --min-api 24, android-35 as library; the
#    output is identical with or without the dependencies on the classpath), then counted with
#    apkanalyzer (methods defined per package) and dexdump (method_ids_size = methods referenced).
# 3. R8 on a minified consumer: the demo app (:app) protected and vulnerable flavors, release
#    (not minified) and minified (R8, the test-only "minified" build type). apkanalyzer with R8's
#    mapping.txt attributes the surviving code to its original packages. The vulnerable flavor has the
#    library on its classpath but never calls it, so R8 removes it except the kept @GuardedEntryPoint.
# 4. The library's runtime dependencies (releaseRuntimeClasspath).
set -euo pipefail

LABEL="${1:?usage: footprint.sh <run label>}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/36.0.0"
AN="$SDK/cmdline-tools/latest/bin/apkanalyzer"
OUT="$REPO/docs/results/$(date +%Y-%m-%d)_footprint_${LABEL}"
[ -e "$OUT" ] && { echo "refusing: $OUT exists" >&2; exit 6; }
mkdir -p "$OUT"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

cd "$REPO"
./gradlew :shezguard-core:assembleRelease :app:assembleProtectedRelease :app:assembleVulnerableRelease \
  :app:assembleProtectedMinified :app:assembleVulnerableMinified --no-watch-fs -q

pkgs() { # <apk> [mapping]: methods defined and dex bytes for the packages of interest
  local m=(); [ $# -gt 1 ] && m=(--proguard-mappings "$2")
  "$AN" dex packages --defined-only ${m[@]+"${m[@]}"} "$1" 2>/dev/null | awk -F'\t' '{split($1,a," "); if (a[1]=="P" && ($4 ~ /^com\.shezguard\.core(\.[a-z]+)?$/ || $4=="com.shezguard.router" || $4=="androidx" || $4=="kotlin")) printf "    %-28s defined methods %6d   dex bytes %8d\n", $4, a[3], $3}'
}

{
  echo "ShezGuard footprint, $(date -u +%Y-%m-%dT%H:%M:%SZ), commit $(git rev-parse HEAD)$(git diff --quiet HEAD -- shezguard-core app || echo ' + uncommitted changes')"
  echo "Tools: $(basename "$BT") d8/dexdump, apkanalyzer $("$AN" --version 2>/dev/null | head -1)"
  echo
  AAR=shezguard-core/build/outputs/aar/shezguard-core-release.aar
  echo "1. Release AAR: $AAR"
  echo "   file bytes: $(wc -c < "$AAR" | tr -d ' ')"
  echo "   entries (uncompressed bytes, compressed bytes, name):"
  unzip -lv "$AAR" | awk 'NR>3 && $1 ~ /^[0-9]+$/ && NF==8 {printf "     %8d %8d  %s\n", $1, $3, $8}'
  echo
  unzip -q -o "$AAR" classes.jar -d "$TMP"
  mkdir -p "$TMP/dex"
  "$BT/d8" --release --min-api 24 --lib "$SDK/platforms/android-35/android.jar" --output "$TMP/dex" "$TMP/classes.jar"
  (cd "$TMP/dex" && zip -q ../lib.apk classes.dex)
  echo "2. classes.jar as dex (d8 --release --min-api 24): $(wc -c < "$TMP/dex/classes.dex" | tr -d ' ') bytes"
  "$BT/dexdump" -f "$TMP/dex/classes.dex" | grep -E 'class_defs_size|method_ids_size|field_ids_size' | sed 's/^/   /'
  echo "   methods defined per package (apkanalyzer; a package row includes its subpackages):"
  pkgs "$TMP/lib.apk"
  echo
  echo "3. Demo app (:app), R8 effect"
  for v in protected/release/app-protected-release-unsigned vulnerable/release/app-vulnerable-release-unsigned \
           protected/minified/app-protected-minified vulnerable/minified/app-vulnerable-minified; do
    f="app/build/outputs/apk/$v.apk"
    echo "  $v.apk"
    echo "    file bytes $("$AN" apk file-size "$f")   download bytes $("$AN" apk download-size "$f")   dex bytes $(unzip -lv "$f" | awk '$NF ~ /^classes[0-9]*\.dex$/ {s+=$1} END{print s}')   methods referenced $("$AN" dex references "$f" | awk '{s+=$2} END{print s}')"
    case "$v" in
      */minified/*) fl="${v%%/*}"; map="app/build/outputs/mapping/${fl}Minified/mapping.txt"
                    pkgs "$f" "$map"
                    echo "    classes from com.shezguard.core in mapping.txt: $(grep -cE '^com\.shezguard\.core\.[^ ]+ -> ' "$map")" ;;
      *) pkgs "$f" ;;
    esac
  done
  echo
  echo "4. :shezguard-core releaseRuntimeClasspath"
  ./gradlew :shezguard-core:dependencies --configuration releaseRuntimeClasspath --no-watch-fs -q | grep -E '^[+\\| ]' | sed 's/^/   /'
} > "$OUT/footprint.txt"
cat "$OUT/footprint.txt"
python3 -I "$REPO/scripts/device/scrub.py" "$OUT" || { echo "SCRUB FAILED: a pattern remains in $OUT" >&2; exit 8; }
