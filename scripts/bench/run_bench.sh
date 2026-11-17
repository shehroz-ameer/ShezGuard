#!/usr/bin/env bash
# Step 14 phase 3: runs the :benchmark instrumented tests on ONE emulator (docs/BENCHMARK.md).
#
# Usage: scripts/bench/run_bench.sh <AVD name> <run label> [port]
#
# Results: docs/results/<date>_<AVD>_api<N>_<run label>/ (refuses to overwrite an existing folder):
#   device.txt                 device, host, build and benchmark settings
#   percall_lines.txt          [BENCH-PERCALL] lines of every per-call run (method A)
#   percall_raw.tar.gz         raw per-call nanoseconds, one file per run and scenario
#   micro_run<k>.json          androidx.benchmark output of each microbenchmark run (method B)
#   instrument_status.txt      the pass/fail lines of every am instrument call
# Raw logcat and the full am instrument output stay in a temporary folder, deleted at the end. Before
# exiting, the results folder is scrubbed (scripts/device/scrub.py) and the run fails if a pattern remains.
#
# Emulator only (the same check as scripts/device/run_shared_tests.sh). Changes no global device setting;
# the test APK is AOT-compiled ("speed") and uninstalled at the end. Every figure from an emulator is "emulator, indicative only".
set -uo pipefail

AVD="${1:?usage: run_bench.sh <AVD> <run label> [port]}"
LABEL="${2:?usage: run_bench.sh <AVD> <run label> [port]}"
case "$LABEL" in *[!A-Za-z0-9._-]*) echo "run label: letters, digits, . _ - only" >&2; exit 2 ;; esac
PORT="${3:-5584}"
PERCALL_RUNS="${PERCALL_RUNS:-5}"
MICRO_RUNS="${MICRO_RUNS:-3}"
SERIAL="emulator-$PORT"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
ADB="$SDK/platform-tools/adb"
EMU="$SDK/emulator/emulator"
PKG=com.shezguard.benchmark.test
RUNNER="$PKG/androidx.benchmark.junit4.AndroidBenchmarkRunner"
MEDIA="/sdcard/Android/media/$PKG"
# androidx.benchmark refuses to run on an emulator unless this error is suppressed; recorded in device.txt.
SUPPRESS="EMULATOR"
a() { "$ADB" -s "$SERIAL" "$@"; }
prop() { a shell getprop "$1" | tr -d '\r'; }

(cd "$REPO" && ./gradlew :benchmark:assembleReleaseAndroidTest --no-watch-fs -q) || { echo "build failed" >&2; exit 5; }
APK="$REPO/benchmark/build/outputs/apk/androidTest/release/benchmark-release-androidTest.apk"

for _ in $(seq 1 60); do "$ADB" devices | grep -q "^$SERIAL" || break; sleep 1; done
if "$ADB" devices | grep -q "^$SERIAL"; then echo "refusing: $SERIAL is already in use" >&2; exit 2; fi

"$EMU" -avd "$AVD" -port "$PORT" -no-snapshot-save -no-boot-anim -no-audio -no-window >/dev/null 2>&1 &
EMU_PID=$!
INSTALLED=0
WORK="$(mktemp -d)"   # full am instrument output and scrub literals: never under docs/results

cleanup() {
  local code=$?
  if [ "$INSTALLED" = 1 ]; then
    a uninstall "$PKG" >/dev/null 2>&1
    a shell rm -rf "$MEDIA" >/dev/null 2>&1
  fi
  sleep 2
  a shell sync >/dev/null 2>&1
  a shell reboot -p >/dev/null 2>&1
  for _ in $(seq 1 60); do kill -0 "$EMU_PID" 2>/dev/null || break; sleep 1; done
  kill -0 "$EMU_PID" 2>/dev/null && { a emu kill >/dev/null 2>&1 || kill "$EMU_PID" 2>/dev/null; }
  wait "$EMU_PID" 2>/dev/null
  rm -rf "$WORK"
  exit $code
}
trap cleanup EXIT INT TERM

"$ADB" -s "$SERIAL" wait-for-device
for _ in $(seq 1 300); do [ "$(prop sys.boot_completed)" = "1" ] && break; sleep 2; done
[ "$(prop sys.boot_completed)" = "1" ] || { echo "boot timed out" >&2; exit 3; }
QEMU="$(prop ro.kernel.qemu)$(prop ro.boot.qemu)"
case "$SERIAL" in emulator-*) ;; *) echo "refusing: not an emulator serial" >&2; exit 4 ;; esac
case "$QEMU" in *1*) ;; *) echo "refusing: no ro.kernel.qemu/ro.boot.qemu=1 (physical device?)" >&2; exit 4 ;; esac

API="$(prop ro.build.version.sdk)"
OUT="$REPO/docs/results/$(date +%Y-%m-%d)_${AVD}_api${API}_${LABEL}"
if [ -e "$OUT" ]; then echo "refusing: $OUT exists (use a new run label)" >&2; exit 6; fi
mkdir -p "$OUT"

# Let the system settle after boot before measuring.
sleep 60
a install -r -t "$APK" >/dev/null || { echo "install failed" >&2; exit 7; }
INSTALLED=1
# Full AOT ("speed") compilation of the test APK, as androidx.benchmark requires (it refuses to measure
# otherwise: NOT-AOT-COMPILED). Applied before both methods, so both measure the same compiled code.
# Affects only this package and is removed with it.
COMPILE_OUT="$(a shell cmd package compile -m speed -f "$PKG" | tr -d '\r' | tr '\n' ' ')"
a shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
a shell input keyevent 82 >/dev/null 2>&1

{
  echo "run_label=$LABEL"
  echo "figures=emulator, indicative only"
  echo "avd=$AVD"
  echo "emulator=yes (ro.kernel.qemu/ro.boot.qemu=$QEMU)"
  echo "emulator_version=$("$EMU" -version 2>/dev/null | head -1)"
  echo "model=$(prop ro.product.model)"
  echo "api=$API"
  echo "release=$(prop ro.build.version.release)"
  echo "fingerprint=$(prop ro.build.fingerprint)"
  echo "security_patch=$(prop ro.build.version.security_patch)"
  echo "abi=$(prop ro.product.cpu.abi)"
  echo "device_cpus_possible=$(a shell cat /sys/devices/system/cpu/possible | tr -d '\r')"
  echo "device_mem=$(a shell grep MemTotal /proc/meminfo | tr -d '\r' | tr -s ' ')"
  echo "host_cpu=$(sysctl -n machdep.cpu.brand_string)"
  echo "host_cores=$(sysctl -n hw.ncpu)"
  echo "host_mem_bytes=$(sysctl -n hw.memsize)"
  echo "host_os=macOS $(sw_vers -productVersion)"
  echo "build=:benchmark release test APK (testBuildType release: not debuggable, not minified), :shezguard-core release variant"
  echo "compilation=cmd package compile -m speed -f: $COMPILE_OUT"
  echo "androidx_benchmark=1.5.0; suppressErrors=$SUPPRESS"
  echo "percall=warmup 2000 + 10000 timed calls per scenario per run; runs=$PERCALL_RUNS (one process each)"
  echo "micro_runs=$MICRO_RUNS (one process each)"
  echo "commit=$(git -C "$REPO" rev-parse HEAD)$(git -C "$REPO" diff --quiet HEAD -- shezguard-core benchmark || echo ' + uncommitted changes in shezguard-core or benchmark')"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/device.txt"
cat "$OUT/device.txt"

a logcat -G 16M >/dev/null 2>&1
: > "$OUT/percall_lines.txt"
for k in $(seq 1 "$PERCALL_RUNS"); do
  a logcat -c
  a shell am instrument -w -r -e class com.shezguard.benchmark.PerCallBenchmark -e run "$k" \
    -e androidx.benchmark.suppressErrors "$SUPPRESS" "$RUNNER" > "$WORK/percall_run${k}_instrument.txt" 2>&1
  echo "percall run $k: $(grep -E '^(OK \(|FAILURES|Tests run|INSTRUMENTATION_CODE)' "$WORK/percall_run${k}_instrument.txt" | tr '\n' ' ')" >> "$OUT/instrument_status.txt"
  a logcat -d -v raw -s System.out:I | tr -d '\r' | grep '^\[BENCH-PERCALL\]' >> "$OUT/percall_lines.txt"
  echo "percall run $k: $(grep -c "run=$k " "$OUT/percall_lines.txt") scenarios"
done
RAW="$(mktemp -d)"
a pull "$MEDIA/percall" "$RAW/" >/dev/null
COPYFILE_DISABLE=1 tar -czf "$OUT/percall_raw.tar.gz" -C "$RAW" percall
rm -rf "$RAW"

for k in $(seq 1 "$MICRO_RUNS"); do
  a shell rm -rf "$MEDIA/additional_test_output"
  a shell am instrument -w -r -e class com.shezguard.benchmark.MicroBenchmark \
    -e androidx.benchmark.suppressErrors "$SUPPRESS" \
    -e additionalTestOutputDir "$MEDIA/additional_test_output" "$RUNNER" > "$WORK/micro_run${k}_instrument.txt" 2>&1
  echo "micro run $k: $(grep -E '^(OK \(|FAILURES|Tests run|INSTRUMENTATION_CODE)' "$WORK/micro_run${k}_instrument.txt" | tr '\n' ' ')" >> "$OUT/instrument_status.txt"
  a pull "$MEDIA/additional_test_output/$PKG-benchmarkData.json" "$OUT/micro_run${k}.json" >/dev/null 2>&1 \
    || { echo "micro run $k: no JSON; am instrument output:"; tail -20 "$WORK/micro_run${k}_instrument.txt"; }
  echo "micro run $k done"
done
# Scrub: device serial numbers and the test APK's certificate fingerprints (from its public certificate),
# written only to $WORK, never printed.
{ prop ro.serialno; prop ro.boot.serialno
  "$SDK/build-tools/36.0.0/apksigner" verify --print-certs "$APK" 2>/dev/null \
    | sed -nE 's/.*certificate SHA-(256|1) digest: ([0-9a-fA-F]+).*/\2/p'
} > "$WORK/literals.txt"
if ! python3 -I "$REPO/scripts/device/scrub.py" "$OUT" --literals "$WORK/literals.txt"; then
  echo "SCRUB FAILED: a pattern remains in ${OUT#$REPO/}" >&2; exit 8
fi
echo "results in ${OUT#$REPO/}"
