#!/usr/bin/env bash
# Benign control (step 12) for PreviewActivity (threat 2): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
# The demo app has no INTERNET permission, so the page itself cannot load in either flavor; the control
# shows that the preview is started for an allowed https link (and that nothing crashes).
echo "== b2b: preview of the app's own page (benign) =="
require_emulator; require_victim
TIMEOUT=15
reset_state
URI="https://shezguard.example/preview?url=https%3A%2F%2Fshezguard.example%2Fhelp"
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "EXPECT: 'ShezDemo ... PreviewActivity: loading the requested page' and no crash."
works_verdict "$VICTIM/\.demo\.PreviewActivity" "ShezDemo.*PreviewActivity: loading the requested page"
