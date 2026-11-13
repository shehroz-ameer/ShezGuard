#!/usr/bin/env bash
# Benign control (step 12) for ForwardActivity (threat 1): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
# adb cannot put an Intent in an extra, so the helper app sends it (attacker/README.md, mode benign_forward).
echo "== b1: forward to a search screen (benign, threat 1 entry point) =="
require_emulator; require_victim; require_attacker
reset_state
echo "REQUEST: the helper app sends ForwardActivity \"next\" = VIEW https://shezguard.example/search?q=mug for SearchActivity."
send "am start -n $ATTACKER/.AttackActivity -e attack benign_forward"
echo "EXPECT: 'ShezDemo ... SearchActivity: results=[Blue mug]' (forwarded, and the search ran)."
works_verdict "$VICTIM/\.demo\.ForwardActivity" "ShezDemo.*SearchActivity: results=\[Blue mug\]"
