#!/usr/bin/env bash
# Step 14: runs :shezguard-core's instrumented tests (src/sharedTest + src/androidTest) on ONE
# emulator and stores the evidence under docs/results/<date>_<avd>_api<N>/.
#
# Usage: scripts/device/run_shared_tests.sh <AVD name> <run label> [port]
#
# The results folder is docs/results/<date>_<AVD>_api<N>_<run label> (e.g. label "phase2-followup").
# The script refuses to run if that folder already exists, so a later run never overwrites an earlier one.
#
# - Boots the AVD on its own port (default 5580) with a cold boot and no snapshot save, and shuts it
#   down at the end.
# - Refuses to run unless the target is an emulator (serial "emulator-*" AND ro.kernel.qemu or
#   ro.boot.qemu = 1). Never run on a physical device: it changes a global setting.
# - Sets `settings put global hidden_api_policy 1` on API 28+ so that the existing reflection in the
#   tests (Intent.mExtras, BaseBundle.isParcelled(), used by N5/N6 checks) is allowed, and restores
#   the previous value from an EXIT trap, also when the run fails or is interrupted. The value used is
#   written to device.txt; results from these runs must say they used it.
# - Phase 2: builds :attacker, pushes it to /data/local/tmp/shezguard-attacker.apk for the caller
#   tests (they reinstall it before each test), and at the end puts the attacker back the way it was
#   (installed with this build if it was installed before, uninstalled otherwise) and deletes the APK.
# - Only filtered output is written to docs/results: device.txt, tagged.txt (the tests' tagged lines,
#   extracted from logcat) and results.txt (one line per test, from the JUnit XML). The raw logcat, the
#   XML and the Gradle output stay in a temporary folder that is deleted at the end. Before exiting, the
#   results folder is scrubbed (scripts/device/scrub.py: API keys, tokens, private-key headers, email
#   addresses, the device serial number, the debug certificate fingerprint) and the run fails if
#   anything still matches (the folder is then deleted). SCRUB_SELFTEST=1 additionally proves, on a temp
#   copy with an injected fake key, that the gate fails the run (exit 8).
set -uo pipefail

AVD="${1:?usage: run_shared_tests.sh <AVD> <run label> [port]}"
LABEL="${2:?usage: run_shared_tests.sh <AVD> <run label> [port]}"
case "$LABEL" in *[!A-Za-z0-9._-]*) echo "run label: letters, digits, . _ - only" >&2; exit 2 ;; esac
PORT="${3:-5580}"
SERIAL="emulator-$PORT"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
ADB="$SDK/platform-tools/adb"
EMU="$SDK/emulator/emulator"
a() { "$ADB" -s "$SERIAL" "$@"; }
prop() { a shell getprop "$1" | tr -d '\r'; }

# adb keeps listing a just-killed emulator for a few seconds; wait up to 60 s for the port to clear.
for _ in $(seq 1 60); do "$ADB" devices | grep -q "^$SERIAL" || break; sleep 1; done
if "$ADB" devices | grep -q "^$SERIAL"; then
  echo "refusing: $SERIAL is already in use" >&2; exit 2
fi

(cd "$REPO" && ./gradlew :attacker:assembleDebug --no-watch-fs -q) || { echo "attacker build failed" >&2; exit 5; }
ATTACKER_APK_LOCAL="$REPO/attacker/build/outputs/apk/debug/attacker-debug.apk"
ATTACKER_APK_DEVICE=/data/local/tmp/shezguard-attacker.apk
ATTACKER_WAS_INSTALLED=""

"$EMU" -avd "$AVD" -port "$PORT" -no-snapshot-save -no-boot-anim -no-audio -no-window >/dev/null 2>&1 &
EMU_PID=$!
POLICY_CHANGED=0
ORIG_POLICY=""

# SettingsProvider writes a change to disk after a short delay (up to about 2 s), and `adb emu kill`
# does not flush it. In phase 1 this lost the restore: the value read back correctly, but the AVD booted
# with the test value next time. So wait, sync, and shut down through Android, not by killing qemu.
shutdown_emulator() {
  sleep 5
  a shell sync >/dev/null 2>&1
  a shell reboot -p >/dev/null 2>&1
  for _ in $(seq 1 60); do kill -0 "$EMU_PID" 2>/dev/null || break; sleep 1; done
  kill -0 "$EMU_PID" 2>/dev/null && { a emu kill >/dev/null 2>&1 || kill "$EMU_PID" 2>/dev/null; }
  wait "$EMU_PID" 2>/dev/null
}

cleanup() {
  local code=$?
  if [ "$POLICY_CHANGED" = 1 ]; then
    if [ "$ORIG_POLICY" = "null" ] || [ -z "$ORIG_POLICY" ]; then
      a shell settings delete global hidden_api_policy >/dev/null
    else
      a shell settings put global hidden_api_policy "$ORIG_POLICY"
    fi
    local after; after="$(a shell settings get global hidden_api_policy | tr -d '\r')"
    echo "hidden_api_policy restored to: $after (was $ORIG_POLICY)"
    [ -n "${OUT:-}" ] && echo "hidden_api_policy_after_restore=$after" >> "$OUT/device.txt"
  fi
  if [ -n "$ATTACKER_WAS_INSTALLED" ]; then
    a shell pm uninstall com.shezguard.attacker >/dev/null 2>&1
    [ "$ATTACKER_WAS_INSTALLED" = yes ] && a shell pm install -t "$ATTACKER_APK_DEVICE" >/dev/null 2>&1
    a shell rm -f "$ATTACKER_APK_DEVICE"
    local att; att="$(a shell pm list packages com.shezguard.attacker | tr -d '\r' | grep -c 'package:com.shezguard.attacker$')"
    local tst; tst="$(a shell pm list packages com.shezguard.core.test | tr -d '\r' | grep -c 'package:com.shezguard.core.test$')"
    echo "attacker restored: installed=$att (was $ATTACKER_WAS_INSTALLED); test APK installed=$tst"
    [ -n "${OUT:-}" ] && { echo "attacker_installed_after=$att"; echo "test_apk_installed_after=$tst"; } >> "$OUT/device.txt"
  fi
  shutdown_emulator
  if [ -n "${WORK:-}" ]; then rm -rf "$WORK"; echo "temp folder removed: $WORK (exists now: $([ -e "$WORK" ] && echo yes || echo no))"; fi
  exit $code
}
trap cleanup EXIT INT TERM
# Created only after the trap is set, so every exit path, including failures and Ctrl-C, removes it.
WORK="$(mktemp -d)"   # raw logcat, JUnit XML, Gradle output, scrub literals: never under docs/results
echo "temp folder: $WORK"

"$ADB" -s "$SERIAL" wait-for-device
for _ in $(seq 1 300); do [ "$(prop sys.boot_completed)" = "1" ] && break; sleep 2; done
[ "$(prop sys.boot_completed)" = "1" ] || { echo "boot timed out" >&2; exit 3; }

# Emulator check: both the serial and a qemu property must say emulator.
QEMU="$(prop ro.kernel.qemu)$(prop ro.boot.qemu)"
case "$SERIAL" in emulator-*) ;; *) echo "refusing: not an emulator serial" >&2; exit 4 ;; esac
case "$QEMU" in *1*) ;; *) echo "refusing: $SERIAL reports no ro.kernel.qemu/ro.boot.qemu=1 (physical device?)" >&2; exit 4 ;; esac

API="$(prop ro.build.version.sdk)"
OUT_TARGET="$REPO/docs/results/$(date +%Y-%m-%d)_${AVD}_api${API}_${LABEL}"
if [ -e "$OUT_TARGET" ]; then echo "refusing: $OUT_TARGET exists (use a new run label)" >&2; exit 6; fi
OUT="$OUT_TARGET"; mkdir -p "$OUT"

if [ "$API" -ge 28 ]; then
  ORIG_POLICY="$(a shell settings get global hidden_api_policy | tr -d '\r')"
  POLICY_CHANGED=1
  a shell settings put global hidden_api_policy 1
fi
USED_POLICY="$(a shell settings get global hidden_api_policy | tr -d '\r')"

# :attacker for the caller tests. Remember whether it was installed (earlier attack runs install it).
if a shell pm list packages com.shezguard.attacker | tr -d '\r' | grep -q 'package:com.shezguard.attacker$'; then
  ATTACKER_WAS_INSTALLED=yes
else
  ATTACKER_WAS_INSTALLED=no
fi
a push "$ATTACKER_APK_LOCAL" "$ATTACKER_APK_DEVICE" >/dev/null
# Wake the screen and dismiss a swipe keyguard, so activities started by another app reach onCreate.
a shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1
a shell input keyevent 82 >/dev/null 2>&1
a shell wm dismiss-keyguard >/dev/null 2>&1

{
  echo "run_label=$LABEL"
  echo "avd=$AVD"
  echo "emulator=yes (ro.kernel.qemu/ro.boot.qemu=$QEMU)"
  echo "model=$(prop ro.product.model)"
  echo "api=$API"
  echo "release=$(prop ro.build.version.release)"
  echo "fingerprint=$(prop ro.build.fingerprint)"
  echo "security_patch=$(prop ro.build.version.security_patch)"
  echo "abi=$(prop ro.product.cpu.abi)"
  echo "hidden_api_policy_before=${ORIG_POLICY:-not read (API < 28, setting not changed)}"
  echo "hidden_api_policy_during_run=$USED_POLICY"
  echo "attacker_installed_before=$ATTACKER_WAS_INSTALLED"
  echo "commit=$(git -C "$REPO" rev-parse HEAD)$(git -C "$REPO" diff --quiet HEAD -- shezguard-core || echo ' + uncommitted changes in shezguard-core')"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/device.txt"
cat "$OUT/device.txt"

a logcat -G 16M >/dev/null 2>&1
a logcat -c
rm -rf "$REPO/shezguard-core/build/outputs/androidTest-results/connected"
(cd "$REPO" && ANDROID_SERIAL="$SERIAL" ./gradlew :shezguard-core:connectedDebugAndroidTest --no-watch-fs -q) > "$WORK/gradle.txt" 2>&1
TEST_EXIT=$?
[ "$TEST_EXIT" = 0 ] || tail -20 "$WORK/gradle.txt" >&2
a logcat -d -v threadtime > "$WORK/logcat.txt"
mkdir -p "$WORK/xml"
find "$REPO/shezguard-core/build/outputs/androidTest-results/connected" -name '*.xml' -exec cp {} "$WORK/xml/" \;
python3 -I "$REPO/scripts/device/extract_tagged.py" "$WORK/logcat.txt" > "$OUT/tagged.txt"
python3 -I "$REPO/scripts/device/junit_summary.py" "$WORK/xml" > "$OUT/results.txt"
head -1 "$OUT/results.txt"

# Scrub: exact values read at run time (device serial numbers, the debug certificate's fingerprints from
# the attacker APK's public certificate; no keystore is read), written only to $WORK, never printed.
{ prop ro.serialno; prop ro.boot.serialno
  "$SDK/build-tools/36.0.0/apksigner" verify --print-certs "$ATTACKER_APK_LOCAL" 2>/dev/null \
    | sed -nE 's/.*certificate SHA-(256|1) digest: ([0-9a-fA-F]+).*/\2/p'
} > "$WORK/literals.txt"
# Gate: mask, then re-scan in check-only mode (every file, any suffix, including archive members). If
# anything still matches, the results folder is deleted and the run fails.
scrub_gate() { # <folder> [check-only]
  if [ "${2:-}" != check-only ]; then
    python3 -I "$REPO/scripts/device/scrub.py" "$1" --literals "$WORK/literals.txt" || return 1
  fi
  python3 -I "$REPO/scripts/device/scrub.py" "$1" --check --literals "$WORK/literals.txt"
}
if ! scrub_gate "$OUT"; then
  rm -rf "$OUT"
  echo "SCRUB FAILED: a pattern remained; ${OUT#$REPO/} was deleted" >&2; exit 8
fi
# SCRUB_SELFTEST=1 proves the gate fails a run: a copy of the (clean) results in the temp folder gets a
# fake API-key-shaped string, built here at run time and never written under docs/results; the gate must
# then fail. The run ends with exit 8 like a real failure; the clean results folder is kept.
if [ "${SCRUB_SELFTEST:-0}" = 1 ]; then
  cp -R "$OUT" "$WORK/selftest"
  FAKE="AIza$(printf 'Z%.0s' $(seq 1 35))"
  echo "selftest $FAKE" >> "$WORK/selftest/tagged.txt"
  if scrub_gate "$WORK/selftest" check-only; then
    echo "SELF-TEST BROKEN: the gate passed a folder containing a fake key" >&2; exit 9
  fi
  echo "SCRUB FAILED (self-test, as intended): the gate rejected the temp copy with the injected string" >&2; exit 8
fi
echo "gradle exit=$TEST_EXIT; results in ${OUT#$REPO/}"
exit $TEST_EXIT
