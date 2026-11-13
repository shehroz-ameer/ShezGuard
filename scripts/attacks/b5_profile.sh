#!/usr/bin/env bash
# Benign control (step 12) for ProfileActivity (threat 5): a legitimate request that must work in BOTH flavors. EMULATOR ONLY.
# Ends with RESULT: WORKS / BROKEN / INCONCLUSIVE (see README.md, "Benign controls").
cd "$(dirname "$0")" && . ./_common.sh
# The helper app sends a legitimate LegacyProfile("alice") (mode benign_profile). Predicted BROKEN in the
# protected flavor by design: a Serializable extra cannot be allow-listed (docs/LIMITATIONS.md L6).
echo "== b5: legitimate profile object (benign) =="
require_emulator; require_victim; require_attacker
reset_state
send "am start -n $ATTACKER/.AttackActivity -e attack benign_profile"
echo "EXPECT: 'ShezDemo ... ProfileActivity: profile=LegacyProfile(name=alice)'."
works_verdict "$VICTIM/\.demo\.ProfileActivity" "ShezDemo.*ProfileActivity: profile=LegacyProfile\(name=alice\)"
