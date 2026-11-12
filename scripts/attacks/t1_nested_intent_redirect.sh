#!/usr/bin/env bash
# Threat 1 (SPEC section 2): intent redirection through a nested Intent extra. EMULATOR ONLY.
# adb cannot put an Intent inside an extra, so the attacker app sends it (attacker/README.md).
cd "$(dirname "$0")" && . ./_common.sh
echo "== t1: nested intent redirection (threat 1) =="
require_emulator; require_victim; require_attacker

echo "CONTROL: the shell (another uid) starts the non-exported InternalAdminActivity directly; it must be refused:"
send "am start -n $VICTIM/.demo.InternalAdminActivity"
reset_state
echo "ATTACK: the attacker app sends ForwardActivity an Intent extra \"next\" that targets InternalAdminActivity."
send "am start -n $ATTACKER/.AttackActivity -e attack nested"
echo "LOOK FOR: 'ShezDemo ... CANARY-ADMIN-REACHED' (the non-exported screen was opened on the attacker's behalf)."
verdict "ShezDemo.*CANARY-ADMIN-REACHED" "$VICTIM/\.demo\.ForwardActivity"
