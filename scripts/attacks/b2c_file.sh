#!/usr/bin/env bash
# Benign control (step 12) for FileViewerActivity (threat 2): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
echo "== b2c: public help file (benign) =="
require_emulator; require_victim
reset_state
URI="https://shezguard.example/file?name=readme.txt"
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "EXPECT: 'ShezDemo ... file content: Public help text'."
works_verdict "$VICTIM/\.demo\.FileViewerActivity" "ShezDemo.*FileViewerActivity: file content: Public help text"
