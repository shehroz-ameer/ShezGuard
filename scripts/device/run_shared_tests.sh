#!/usr/bin/env bash
# Step 14: runs :shezguard-core's instrumented tests (src/sharedTest + src/androidTest) on ONE
# emulator and stores the evidence under docs/results/<date>_<avd>_api<N>/.
#
# Usage: scripts/device/run_shared_tests.sh <AVD name> [port]
#
# - Boots the AVD on its own port (default 5580) with a cold boot and no snapshot save, and shuts it
#   down at the end.
# - Refuses to run unless the target is an emulator (serial "emulator-*" AND ro.kernel.qemu or
#   ro.boot.qemu = 1). Never run on a physical device: it changes a global setting.
# - Sets `settings put global hidden_api_policy 1` on API 28+ so that the existing reflection in the
#   tests (Intent.mExtras, BaseBundle.isParcelled(), used by N5/N6 checks) is allowed, and restores
#   the previous value from an EXIT trap, also when the run fails or is interrupted. The value used is
#   written to device.txt; results from these runs must say they used it.
set -uo pipefail

AVD="${1:?usage: run_shared_tests.sh <AVD> [port]}"
PORT="${2:-5580}"
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
  shutdown_emulator
  exit $code
}
trap cleanup EXIT INT TERM

"$ADB" -s "$SERIAL" wait-for-device
for _ in $(seq 1 300); do [ "$(prop sys.boot_completed)" = "1" ] && break; sleep 2; done
[ "$(prop sys.boot_completed)" = "1" ] || { echo "boot timed out" >&2; exit 3; }

# Emulator check: both the serial and a qemu property must say emulator.
QEMU="$(prop ro.kernel.qemu)$(prop ro.boot.qemu)"
case "$SERIAL" in emulator-*) ;; *) echo "refusing: not an emulator serial" >&2; exit 4 ;; esac
case "$QEMU" in *1*) ;; *) echo "refusing: $SERIAL reports no ro.kernel.qemu/ro.boot.qemu=1 (physical device?)" >&2; exit 4 ;; esac

API="$(prop ro.build.version.sdk)"
OUT="$REPO/docs/results/$(date +%Y-%m-%d)_${AVD}_api${API}"
rm -rf "$OUT"; mkdir -p "$OUT"

if [ "$API" -ge 28 ]; then
  ORIG_POLICY="$(a shell settings get global hidden_api_policy | tr -d '\r')"
  POLICY_CHANGED=1
  a shell settings put global hidden_api_policy 1
fi
USED_POLICY="$(a shell settings get global hidden_api_policy | tr -d '\r')"

{
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
  echo "commit=$(git -C "$REPO" rev-parse HEAD)$(git -C "$REPO" diff --quiet HEAD -- shezguard-core || echo ' + uncommitted changes in shezguard-core')"
  echo "date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUT/device.txt"
cat "$OUT/device.txt"

a logcat -G 16M >/dev/null 2>&1
a logcat -c
rm -rf "$REPO/shezguard-core/build/outputs/androidTest-results/connected"
(cd "$REPO" && ANDROID_SERIAL="$SERIAL" ./gradlew :shezguard-core:connectedDebugAndroidTest --no-watch-fs -q) > "$OUT/gradle.txt" 2>&1
TEST_EXIT=$?
a logcat -d -v threadtime > "$OUT/logcat.txt"
find "$REPO/shezguard-core/build/outputs/androidTest-results/connected" -name '*.xml' -exec cp {} "$OUT/" \;
python3 -I "$REPO/scripts/device/extract_tagged.py" "$OUT/logcat.txt" > "$OUT/tagged.txt"
echo "gradle exit=$TEST_EXIT; results in ${OUT#$REPO/}"
exit $TEST_EXIT
