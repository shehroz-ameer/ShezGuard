#!/usr/bin/env bash
# Benign control (step 12) for NoteActivity (threat 2): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
echo "== b2d: short note (benign) =="
require_emulator; require_victim
reset_state
send "am start -n $VICTIM/.demo.NoteActivity --es note 'Buy milk' --ei copies 2"
echo "EXPECT: 'ShezDemo ... note length=8 copies=2 preview length=16'."
works_verdict "$VICTIM/\.demo\.NoteActivity" "ShezDemo.*NoteActivity: note length=8 copies=2 preview length=16"
