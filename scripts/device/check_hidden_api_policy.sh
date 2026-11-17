#!/usr/bin/env bash
# Step 14: cold-boots one AVD, prints hidden_api_policy, optionally resets it to "unset" (the value the
# phase 1 runs found on every AVD), and with --reset proves the reset persisted by booting a second time.
# Emulators only (same check as run_shared_tests.sh).
# Usage: scripts/device/check_hidden_api_policy.sh <AVD> [--reset] [port]
set -uo pipefail
AVD="$1"; RESET="${2:-}"; PORT="${3:-5582}"; SERIAL="emulator-$PORT"
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"; ADB="$SDK/platform-tools/adb"; EMU="$SDK/emulator/emulator"
a() { "$ADB" -s "$SERIAL" "$@"; }
boot() {
  for _ in $(seq 1 60); do "$ADB" devices | grep -q "^$SERIAL" || break; sleep 1; done
  "$EMU" -avd "$AVD" -port "$PORT" -no-snapshot-save -no-boot-anim -no-audio -no-window >/dev/null 2>&1 &
  EMU_PID=$!
  a wait-for-device
  for _ in $(seq 1 300); do [ "$(a shell getprop sys.boot_completed | tr -d '\r')" = "1" ] && break; sleep 2; done
  case "$(a shell getprop ro.kernel.qemu | tr -d '\r')$(a shell getprop ro.boot.qemu | tr -d '\r')" in *1*) ;; *) echo "refusing: not an emulator" >&2; a emu kill; exit 4 ;; esac
}
down() { sleep 5; a shell sync; a shell reboot -p >/dev/null 2>&1; for _ in $(seq 1 60); do kill -0 "$EMU_PID" 2>/dev/null || break; sleep 1; done; kill -0 "$EMU_PID" 2>/dev/null && a emu kill; wait "$EMU_PID" 2>/dev/null; }
get() { a shell settings get global hidden_api_policy | tr -d '\r'; }
boot; echo "$AVD boot 1: hidden_api_policy=$(get)"
if [ "$RESET" = "--reset" ]; then a shell settings delete global hidden_api_policy >/dev/null; echo "$AVD after delete: $(get)"; fi
down
if [ "$RESET" = "--reset" ]; then boot; echo "$AVD boot 2 (cold): hidden_api_policy=$(get)"; down; fi
