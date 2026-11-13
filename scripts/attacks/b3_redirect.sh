#!/usr/bin/env bash
# Benign control (step 12) for RedirectActivity (threat 3): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
# The redirect target is opened by whatever handles https://shezguard.example/help (a browser); the
# control checks that the demo app itself issued that VIEW (no BROWSABLE category, unlike the adb launch).
echo "== b3: redirect to the app's own site (benign) =="
require_emulator; require_victim
reset_state
URI="https://shezguard.example/redirect?next=https%3A%2F%2Fshezguard.example%2Fhelp"
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "EXPECT: 'ShezDemo ... continuing to the next page' and 'START u0 {act=android.intent.action.VIEW dat=https://shezguard.example/...'."
works_verdict "$VICTIM/\.demo\.RedirectActivity" "ShezDemo.*RedirectActivity: continuing to the next page" \
    "START u0 \{act=android\.intent\.action\.VIEW dat=https://shezguard\.example/"
