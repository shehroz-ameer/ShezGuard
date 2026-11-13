#!/usr/bin/env bash
# Benign control (step 12) for SearchActivity (threat 2): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
echo "== b2a: normal search (benign) =="
require_emulator; require_victim
reset_state
URI="https://shezguard.example/search?q=blue%20mug"
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "EXPECT: 'ShezDemo ... results=[Blue mug]'."
works_verdict "$VICTIM/\.demo\.SearchActivity" "ShezDemo.*SearchActivity: results=\[Blue mug\]"
