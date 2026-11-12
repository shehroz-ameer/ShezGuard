#!/usr/bin/env bash
# Threat 5 (SPEC section 2): malformed or hostile Serializable extras. EMULATOR ONLY.
# adb cannot send a Serializable, so the attacker app does (attacker/README.md).
#   t5_malformed_bundle.sh           unknown class -> the demo app crashes while unparcelling
#   t5_malformed_bundle.sh gadget    5b: the demo app's own LegacyProfile.readObject side effect runs
cd "$(dirname "$0")" && . ./_common.sh
MODE="${1:-unknown}"
require_emulator; require_victim; require_attacker
reset_state
if [ "$MODE" = "gadget" ]; then
    echo "== t5 (5b): deserialisation gadget (threat 5) =="
    echo "ATTACK: the attacker app sends ProfileActivity a LegacyProfile (a class the demo app has)."
    send "am start -n $ATTACKER/.AttackActivity -e attack gadget"
    echo "LOOK FOR: 'ShezDemo ... CANARY-GADGET-... side effect ran during deserialisation'."
    verdict "ShezDemo.*CANARY-GADGET-" "$VICTIM/\.demo\.ProfileActivity"
else
    echo "== t5: Serializable of an unknown class (threat 5) =="
    echo "ATTACK: the attacker app sends ProfileActivity a Serializable whose class the demo app does not have."
    send "am start -n $ATTACKER/.AttackActivity -e attack serializable_unknown"
    echo "LOOK FOR: a crash of $VICTIM in 'logcat -b crash' (ClassNotFoundException while unparcelling)."
    verdict "" "$VICTIM/\.demo\.ProfileActivity"
fi
