# Attack scripts (emulator only)

> **Warning.** These scripts attack the deliberately vulnerable demo app `com.shezguard.router`. They
> refuse to run unless exactly one device is connected **and it is an emulator**
> (`ro.kernel.qemu` / `ro.boot.qemu` / `ro.hardware`). `ALLOW_PHYSICAL_DEVICE=1` overrides this; do
> not use it on a phone you use.

One script per entry point, named by threat number (`docs/SPEC.md` section 2):

| Script | Threat | Needs `:attacker` | Evidence of success |
|---|---|---|---|
| `t1_nested_intent_redirect.sh` | 1 | yes | `CANARY-ADMIN-REACHED` (non-exported screen opened) |
| `t2a_sql_injection.sh` | 2 | no | `CANARY-HIDDEN-ROW-*` in the search results |
| `t2b_webview_url.sh` | 2 | no | `CANARY-SECRET-7f3a` (file://) or `CANARY-JS-42` (script ran) |
| `t2c_path_traversal.sh` | 2 | no | `CANARY-SECRET-7f3a` |
| `t2d_oversized_extra.sh` | 2 | no | a crash of the demo app |
| `t3_open_redirect.sh` | 3 | yes | `CANARY-REDIRECT-LANDED` logged by the attacker app |
| `t4_link_hijack.sh` | 4 | yes | the attacker app logs the login token |
| `t5_malformed_bundle.sh` | 5 | yes | a crash of the demo app |
| `t5_malformed_bundle.sh gadget` | 5 (5b) | yes | `CANARY-GADGET-*` (a `readObject` side effect ran) |
| `t6_encoding_manual_check.sh` | 6 | no | `CANARY-SECRET-7f3a` after an encoded payload |

Every script clears logcat (all buffers, including `crash`), force-stops both apps, sends the
attack, prints exactly what it sent, what to look for, and the evidence, and ends with one line:

- `RESULT: EXPLOITED`: the canary appeared in logcat, or the demo app crashed (`logcat -b crash`).
- `RESULT: NOT_EXPLOITED`: the attack reached the demo app (a `START` of the target component is in
  logcat), and neither happened within the timeout.
- `RESULT: INCONCLUSIVE` (exit code 2): no device, wrong device, app not installed, or no evidence
  the attack was delivered.

Two platform behaviours the scripts work around (observed in step 11):
- **`logcat -c` does not clear on the API 29 Google Play emulator image** (a `user` build): it exits
  0 (or prints `failed to clear the 'main' log`) and every entry stays. A canary or crash from an
  earlier script would then count again. So every log read is bounded by time
  (`logcat -T "$SINCE"`, where `SINCE` is taken after the reset); clearing is still attempted.
- **`am start -W` never returns on API 29** when the started activity finishes inside `onCreate`
  (as a forwarding entry point, or a blocked one in step 12, does). The scripts use `am start`
  without `-W` and poll the logs instead.

No payload contains the canary it looks for; canaries come only from data the attack must not reach,
or from code that must not run. The scripts are flavor-agnostic: they print the installed
`versionName` (`1.0-vulnerable` / `1.0-protected`) and are reused unchanged in step 12.

`t3` and `t4` simulate one user choice: that the attacker app was picked to open its links
(`pm set-app-links-user-selection` on API 31+, `pm set-app-link ... always` below). Android does not
pick a handler for an unverified link on its own; the scripts undo the setting before they finish.

```sh
./gradlew :app:installVulnerableDebug :attacker:installDebug
scripts/attacks/run_all.sh                 # one RESULT line per script
scripts/attacks/t2a_sql_injection.sh       # full evidence for one attack
ANDROID_SERIAL=emulator-5556 scripts/attacks/t5_malformed_bundle.sh gadget
```
