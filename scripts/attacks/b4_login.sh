#!/usr/bin/env bash
# Benign control (step 12) for LinkActivity (threat 4): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
#   b4_login.sh          https://shezguard.example/login?token=abc123
#   b4_login.sh custom   shezdemo://login?token=abc123
# Sent with an explicit package (as the app's own link handling would deliver it), so the hijack of t4
# does not interfere with the control.
MODE="${1:-https}"
echo "== b4: login link, $MODE (benign) =="
require_emulator; require_victim
reset_state
if [ "$MODE" = "custom" ]; then URI="shezdemo://login?token=abc123"; else URI="https://shezguard.example/login?token=abc123"; fi
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "EXPECT: 'ShezDemo ... LinkActivity: signed in with a one-time token'."
works_verdict "$VICTIM/\.demo\.LinkActivity" "ShezDemo.*LinkActivity: signed in with a one-time token"
