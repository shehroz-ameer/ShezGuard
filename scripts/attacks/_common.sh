# Shared helpers for scripts/attacks/*.sh (step 11). Sourced, not run. Bash 3.2 compatible (macOS).
#
# EMULATOR ONLY. These scripts attack com.shezguard.router, a deliberately vulnerable demo app.
# They refuse to run against anything that is not an emulator unless ALLOW_PHYSICAL_DEVICE=1.
#
# Every script: clears logcat (all buffers), force-stops the apps, sends the attack, then prints the
# evidence and ends with exactly one machine-readable line:
#   RESULT: EXPLOITED      the canary appeared in logcat, or the demo app crashed (logcat -b crash)
#   RESULT: NOT_EXPLOITED  the attack reached the demo app, and neither happened within the timeout
#   RESULT: INCONCLUSIVE   the attack could not be shown to reach the app (setup problem, no device, ...)
# The scripts work unchanged for both flavors (vulnerable, protected); they print which one is installed.

VICTIM=com.shezguard.router
ATTACKER=com.shezguard.attacker
ADB="${ADB:-$(command -v adb || echo "${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb")}"
TIMEOUT="${TIMEOUT:-10}"

CLEANUP_HOOK=""

adb_sh() { "$ADB" shell "$@" | tr -d '\r'; }

# Ends the script: runs the cleanup hook silently, then prints the RESULT line last.
finish() {
    if [ -n "$CLEANUP_HOOK" ]; then "$CLEANUP_HOOK" >/dev/null 2>&1; fi
    echo "RESULT: $1"
    if [ "$1" = "INCONCLUSIVE" ]; then exit 2; fi
    exit 0
}

inconclusive() { echo "INCONCLUSIVE: $1"; finish INCONCLUSIVE; }

require_emulator() {
    [ -x "$ADB" ] || inconclusive "adb not found (set ADB=/path/to/adb)"
    if [ -z "${ANDROID_SERIAL:-}" ]; then
        local n
        n=$("$ADB" devices | awk 'NR>1 && $2=="device"' | wc -l | tr -d ' ')
        [ "$n" = "1" ] || inconclusive "need exactly one connected device, found $n (or set ANDROID_SERIAL)"
    fi
    local qemu1 qemu2 hw
    qemu1=$(adb_sh getprop ro.kernel.qemu); qemu2=$(adb_sh getprop ro.boot.qemu); hw=$(adb_sh getprop ro.hardware)
    if [ "$qemu1" != "1" ] && [ "$qemu2" != "1" ] && [ "$hw" != "ranchu" ] && [ "$hw" != "goldfish" ]; then
        if [ "${ALLOW_PHYSICAL_DEVICE:-0}" != "1" ]; then
            inconclusive "the connected device is not an emulator; refusing (ALLOW_PHYSICAL_DEVICE=1 overrides)"
        fi
        echo "WARNING: running on a physical device because ALLOW_PHYSICAL_DEVICE=1"
    fi
    API=$(adb_sh getprop ro.build.version.sdk)
    echo "DEVICE: $(adb_sh getprop ro.product.model), Android $(adb_sh getprop ro.build.version.release), API $API"
}

# Prints the installed flavor of the demo app ("1.0-vulnerable" / "1.0-protected").
require_victim() {
    local v
    v=$(adb_sh dumpsys package "$VICTIM" | grep -m1 'versionName=' | sed 's/.*versionName=//')
    [ -n "$v" ] || inconclusive "$VICTIM is not installed (see app/README.md)"
    echo "TARGET: $VICTIM $v"
}

require_attacker() {
    local v
    v=$(adb_sh dumpsys package "$ATTACKER" | grep -m1 'versionName=' | sed 's/.*versionName=//')
    [ -n "$v" ] || inconclusive "$ATTACKER is not installed (see attacker/README.md)"
    echo "ATTACKER: $ATTACKER $v"
}

# Clears logcat, force-stops both apps, and records SINCE, the device time from which logs count.
# Clearing alone is not enough: on the API 29 Google Play emulator image (a user build), `logcat -c`
# from adb exits 0 but leaves every entry in place (observed in step 11). So every read below uses
# `logcat -T "$SINCE"`. SINCE is the current second, rounded down, taken 1 s after the reset, so no
# earlier line can fall at or after it, and every line the attack causes does.
reset_state() {
    "$ADB" logcat -b all -c 2>/dev/null # on API 29 prints "failed to clear the 'main' log"
    adb_sh am force-stop "$VICTIM" >/dev/null
    adb_sh am force-stop "$ATTACKER" >/dev/null
    sleep 1
    SINCE=$(adb_sh "date +'%m-%d %H:%M:%S.000'")
    echo "LOGS FROM: $SINCE (device time)"
}

# logs [logcat options...]: this run's log lines only (since SINCE).
logs() { "$ADB" logcat -d -T "$SINCE" "$@" | tr -d '\r' | grep -v '^-----'; }

# send "<shell command>": prints exactly what is sent, then runs it on the device.
# Scripts use `am start` without -W: on API 29, `am start -W` never returns for an activity that
# finishes inside onCreate (observed in step 11), which a blocked or forwarding entry point does.
send() {
    echo "SEND: $1"
    adb_sh "$1" | sed 's/^/  am: /'
}

app_log() { logs -s 'ShezDemo:*' 'ShezAttacker:*' 'ShezGuard:*'; }
# A Java crash ("Process: <pkg>") or a native crash (tombstone line ">>> <pkg> <<<", plus its signal line).
# Native crashes were missed before step 12: a minified build crashed with SIGSEGV and the verdict said
# NOT_EXPLOITED (docs/ATTACK_MATRIX.md, R8 section).
crash_log() { logs -b crash | grep -E -A6 "Process: $VICTIM|>>> $VICTIM <<<"; }

# verdict <canary ERE or ""> <delivered ERE>
#   EXPLOITED if the canary appears in logcat or the demo app crashed; NOT_EXPLOITED if the attack
#   was delivered (a START of a component matching <delivered ERE> is in logcat) and neither happened
#   within TIMEOUT seconds; INCONCLUSIVE otherwise.
verdict() {
    local canary="$1" delivered="$2" i=0 hit="" crash=""
    while [ "$i" -lt "$TIMEOUT" ]; do
        crash=$(crash_log)
        if [ -n "$canary" ]; then hit=$(logs | grep -E "$canary"); fi
        if [ -n "$crash" ] || [ -n "$hit" ]; then break; fi
        sleep 1; i=$((i + 1))
    done
    echo "---- app log (ShezDemo / ShezAttacker / ShezGuard) ----"
    app_log
    if [ -n "$crash" ]; then
        echo "---- crash buffer: $VICTIM crashed ----"
        echo "$crash"
        finish EXPLOITED
    fi
    if [ -n "$hit" ]; then
        echo "---- canary found ----"
        echo "$hit"
        finish EXPLOITED
    fi
    if logs | grep -E "START u0 .*cmp=($delivered)" >/dev/null; then
        echo "---- delivered, no canary and no crash within ${TIMEOUT}s ----"
        finish NOT_EXPLOITED
    fi
    inconclusive "no evidence that the attack reached $VICTIM (no START of $delivered in logcat)"
}

# ---- Benign controls (step 12) ----
# works_verdict <delivered ERE> <expected ERE>...
#   For the b*.sh scripts. Ends with one line:
#   RESULT: WORKS         every expected ERE matched this run's logs within TIMEOUT, and the app did not crash
#   RESULT: BROKEN        the request reached the app (START of <delivered ERE>), but an expected line is
#                         missing within TIMEOUT, or the demo app crashed
#   RESULT: INCONCLUSIVE  no evidence the request reached the app
works_verdict() {
    local delivered="$1" i=0 crash="" missing="" e
    shift
    while [ "$i" -lt "$TIMEOUT" ]; do
        crash=$(crash_log)
        missing=""
        for e in "$@"; do logs | grep -E "$e" >/dev/null || missing="$missing [$e]"; done
        if [ -n "$crash" ] || [ -z "$missing" ]; then break; fi
        sleep 1; i=$((i + 1))
    done
    echo "---- app log (ShezDemo / ShezAttacker / ShezGuard) ----"
    app_log
    if [ -n "$crash" ]; then
        echo "---- crash buffer: $VICTIM crashed ----"
        echo "$crash"
        finish BROKEN
    fi
    if [ -z "$missing" ]; then
        echo "---- every expected line found ----"
        for e in "$@"; do logs | grep -E -m1 "$e"; done
        finish WORKS
    fi
    if logs | grep -E "START u0 .*cmp=($delivered)" >/dev/null; then
        echo "---- delivered, but missing within ${TIMEOUT}s:$missing ----"
        finish BROKEN
    fi
    inconclusive "no evidence that the request reached $VICTIM (no START of $delivered in logcat)"
}
