#!/usr/bin/env bash
# Benign control (step 12) for ManualCheckActivity (threat 6): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
echo "== b6: public help file behind the manual check (benign) =="
require_emulator; require_victim
reset_state
URI="https://shezguard.example/manual?name=readme.txt"
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "EXPECT: 'ShezDemo ... file content: Public help text'."
works_verdict "$VICTIM/\.demo\.ManualCheckActivity" "ShezDemo.*ManualCheckActivity: file content: Public help text"
