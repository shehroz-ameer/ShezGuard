#!/usr/bin/env bash
# Runs every benign control (step 12) and prints one summary line per script. EMULATOR ONLY.
cd "$(dirname "$0")"
for s in b1_forward.sh b2a_search.sh b2b_preview.sh b2c_file.sh b2d_note.sh b3_redirect.sh b4_login.sh \
         "b4_login.sh custom" b5_profile.sh b6_manual.sh; do
    out=$(bash $s 2>&1)
    printf '%-36s %s\n' "$s" "$(echo "$out" | grep '^RESULT:' | tail -1)"
done
