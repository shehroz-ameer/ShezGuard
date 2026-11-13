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
| `t2d_oversized_extra.sh copies` | 2 | no | a crash of the demo app (short note, huge `copies`; step 12) |
| `t3_open_redirect.sh` | 3 | yes | `CANARY-REDIRECT-LANDED` logged by the attacker app |
| `t4_link_hijack.sh` | 4 | yes | the attacker app logs the login token |
| `t5_malformed_bundle.sh` | 5 | yes | a crash of the demo app |
| `t5_malformed_bundle.sh gadget` | 5 (5b) | yes | `CANARY-GADGET-*` (a `readObject` side effect ran) |
| `t6_encoding_manual_check.sh` | 6 | no | `CANARY-SECRET-7f3a` after an encoded payload |

Every script clears logcat (all buffers, including `crash`), force-stops both apps, sends the
attack, prints exactly what it sent, what to look for, and the evidence, and ends with one line:

- `RESULT: EXPLOITED`: the canary appeared in logcat, or the demo app crashed (`logcat -b crash`: a
  Java crash, `Process: com.shezguard.router`, or, from step 12, a native crash, the tombstone line
  `>>> com.shezguard.router <<<`).
- `RESULT: NOT_EXPLOITED`: the attack reached the demo app (a `START` of the target component is in
  logcat), and neither happened within the timeout.
- `RESULT: INCONCLUSIVE` (exit code 2): no device, wrong device, app not installed, or no evidence
  the attack was delivered.

**Fixed in step 12: native crashes were missed.** Until step 12, `crash_log` matched only Java crashes.
A minified build with an insufficient keep rule crashed natively (SIGSEGV in ART) on `t5 gadget`, and
the verdict said `NOT_EXPLOITED`. The step 11 results are not affected: every step 11 result was
already `EXPLOITED`, and this fix can only turn `NOT_EXPLOITED` into `EXPLOITED`. Every step 12 result
in `docs/ATTACK_MATRIX.md` comes from runs made after the fix.

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

## Benign controls (step 12)

One legitimate request per entry point. It must work in **both** flavors, so that a protection that
breaks the feature shows up. Same helpers (`_common.sh`, `works_verdict`). Each ends with one line:

- `RESULT: WORKS`: every expected log line of the normal feature appeared, and the app did not crash.
- `RESULT: BROKEN`: the request reached the app, but an expected line is missing within the timeout,
  or the app crashed.
- `RESULT: INCONCLUSIVE` (exit code 2): no evidence that the request reached the app.

| Script | Request | Expected |
|---|---|---|
| `b1_forward.sh` | helper app (`benign_forward`): `next` = search link for `SearchActivity` | `SearchActivity: results=[Blue mug]` |
| `b2a_search.sh` | `/search?q=blue%20mug` | `results=[Blue mug]` |
| `b2b_preview.sh` | `/preview?url=https://shezguard.example/help` (encoded) | `loading the requested page` (the page itself cannot load: no INTERNET permission, in both flavors) |
| `b2c_file.sh` | `/file?name=readme.txt` | `file content: Public help text` |
| `b2d_note.sh` | `note="Buy milk"`, `copies=2` | `note length=8 copies=2 preview length=16` |
| `b3_redirect.sh` | `/redirect?next=https://shezguard.example/help` (encoded) | `continuing to the next page` and the app's own `START ... VIEW dat=https://shezguard.example/` |
| `b4_login.sh [custom]` | `https://shezguard.example/login?token=abc123` or `shezdemo://login?token=abc123`, explicit package | `signed in with a one-time token` |
| `b5_profile.sh` | helper app (`benign_profile`): `LegacyProfile("alice")` | `profile=LegacyProfile(name=alice)` |
| `b6_manual.sh` | `/manual?name=readme.txt` | `file content: Public help text` |

```sh
./gradlew :app:installVulnerableDebug :attacker:installDebug
scripts/attacks/run_all.sh                 # one RESULT line per attack script
scripts/attacks/run_benign.sh              # one RESULT line per benign control
scripts/attacks/t2a_sql_injection.sh       # full evidence for one attack
ANDROID_SERIAL=emulator-5556 scripts/attacks/t5_malformed_bundle.sh gadget
```
