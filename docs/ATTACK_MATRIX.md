# Attack matrix

One row per attack against the demo app (`:app`, step 11), with the result **observed** when the
script in `scripts/attacks/` was run. A result is recorded only if the script was actually run and
its output seen; everything else says "not run". The protected column is filled in by step 12, by
re-running the same scripts unchanged against the `protected` flavor.

Result values are the scripts' own `RESULT:` lines (`scripts/attacks/README.md`): EXPLOITED (the
canary appeared, or the app crashed), NOT_EXPLOITED, INCONCLUSIVE.

## Runs

| Run | Date | Device | Android | Flavor | Apps |
|---|---|---|---|---|---|
| R1 | 2026-11-12 | Pixel_8 AVD (`sdk_gphone64_arm64`, Google Play image), build `UE1A.230829.036.A4`, security patch 2023-09-05 | 14 (API 34) | `1.0-vulnerable` (debug) | `:app` and `:attacker` from the uncommitted step 11 working tree on top of `111367a` |
| R2 | 2026-11-12 | Pixel_4 AVD (`Android SDK built for arm64`, Google Play image), build `QSR1.211112.011`, security patch 2019-09-05 | 10 (API 29) | `1.0-vulnerable` (debug) | same APKs as R1 |

Both runs used the final scripts (logs bounded by time, `am start` without `-W`; see
`scripts/attacks/README.md`). An earlier API 29 attempt was discarded: `logcat -c` does not clear on
that image, so evidence from one script leaked into the next. It is not recorded here.

## Results (step 11: vulnerable flavor)

| Attack | Threat | Script | Entry point | Vulnerable, API 34 (R1) | Vulnerable, API 29 (R2) | Protected (step 12) | Evidence |
|---|---|---|---|---|---|---|---|
| Nested Intent extra forwarded to a non-exported activity | 1 | `t1_nested_intent_redirect.sh` | `ForwardActivity` | EXPLOITED | EXPLOITED | not run yet | Both: control (the shell starts `InternalAdminActivity` directly) failed with `SecurityException ... not exported`; via `ForwardActivity`, sent by `:attacker`: `CANARY-ADMIN-REACHED`. |
| SQL injection via `?q=` | 2 | `t2a_sql_injection.sh` | `SearchActivity` | EXPLOITED | EXPLOITED | not run yet | Both: `q=x' OR hidden=1 --` returned both `CANARY-HIDDEN-ROW-*` rows. |
| Attacker URL loaded into a WebView via `?url=` | 2 | `t2b_webview_url.sh` | `PreviewActivity` | EXPLOITED | EXPLOITED | not run yet | Both: `file:///data/user/0/com.shezguard.router/files/secret.txt` showed `CANARY-SECRET-7f3a`; a `data:` page ran its script (`console: CANARY-JS-42`). |
| Path traversal via `?name=` | 2 | `t2c_path_traversal.sh` | `FileViewerActivity` | EXPLOITED | EXPLOITED | not run yet | Both: `name=../secret.txt` read `CANARY-SECRET-7f3a`. |
| Oversized extras (denial of service) | 2 | `t2d_oversized_extra.sh` | `NoteActivity` | EXPLOITED (crash) | EXPLOITED (crash) | not run yet | 64 000-character `note`, `copies=20000`: `OutOfMemoryError` in `NoteActivity.handle` (API 34: "Failed to allocate a 1280000016 byte allocation"; API 29: "a 2560000016 byte allocation"). |
| Open redirect via `?next=` | 3 | `t3_open_redirect.sh` | `RedirectActivity` | EXPLOITED | EXPLOITED | not run yet | Both: `next=https://attacker.invalid/login` opened `:attacker`'s `LandingActivity` (`CANARY-REDIRECT-LANDED on attacker.invalid`). Simulated user choice of `:attacker` for `attacker.invalid` (API 34: `pm set-app-links-user-selection`; API 29: `pm set-app-link ... always`). |
| Deep link hijacking (custom scheme; https without `autoVerify`) | 4 | `t4_link_hijack.sh` | `LinkActivity` | EXPLOITED | EXPLOITED | **not prevented at runtime; detected at build time (step 13)** | Both: `cmd package query-activities` lists `com.shezguard.attacker/.HijackActivity` as a handler of `shezdemo://login` (2 handlers) and of `https://shezguard.example/login` (3, with Chrome). API 34 `pm get-app-links --user 0`: `shezguard.example` not verified ("Disabled"). With the user's choice of `:attacker` simulated, a login link opened without a target package went to `:attacker`, which logged `HIJACKED ... token=CANARY-TOKEN-…`. |
| Serializable of an unknown class (malformed Bundle) | 5 | `t5_malformed_bundle.sh` | `ProfileActivity` | EXPLOITED (crash) | EXPLOITED (crash) | not run yet | Both crash in `Intent.getSerializableExtra` called from `ProfileActivity.handle`. API 34: `BadParcelableException`, one lazy value (`BaseBundle.unwrapLazyValueFromMapLocked`). API 29: `RuntimeException: Parcelable encountered ClassNotFoundException`, while the whole Bundle is unparcelled (`BaseBundle.unparcel` → `initializeFromParcelLocked`). |
| Deserialisation gadget (`LegacyProfile.readObject`) | 5 (5b) | `t5_malformed_bundle.sh gadget` | `ProfileActivity` | EXPLOITED | EXPLOITED | **not prevented** (see note) | Both: `CANARY-GADGET-24 side effect ran during deserialisation`. |
| Encoding evasion of a manual `..` check | 6 | `t6_encoding_manual_check.sh` | `ManualCheckActivity` | EXPLOITED | EXPLOITED | not run yet | Both: control (raw `../secret.txt`) was rejected by the manual check; `%2e%2e%2fsecret.txt` and `%252e%252e%252fsecret.txt` passed it and read `CANARY-SECRET-7f3a`. |

Notes:
- **Threat 4** is a property of the manifest, not of the code that handles the intent: the OS decides
  which app receives the link before any app code runs. ShezGuard cannot prevent it at runtime
  (`requireVerifiedDomain` reports domain state as a signal only, L3, L32); the step 13 build-time
  check flags custom schemes and `BROWSABLE` filters without `autoVerify`.
- **Threat 5b** is expected to stay exploitable in the protected flavor: ShezGuard reads every extra
  to find nested intents, so the gadget's `readObject` runs inside ShezGuard before any decision
  (`docs/LIMITATIONS.md` L1, L27). Step 12 records the observed result. A minified build needs a
  keep rule for `LegacyProfile.readObject`, or R8 may remove the gadget and change this result.
- **`t3` and `t4` simulate one user choice** (see `scripts/attacks/README.md`). The vulnerability in
  `t3` (the app opens any URL it is given) does not depend on it; it only makes the landing visible.
- **`t2d` uses a large `note`.** A small note with a very large `copies` (an int) would also exhaust
  the heap; ShezGuard's extras rule bounds strings and arrays, not int values. Not run yet.
- Release builds: R1 and R2 used debug builds. A minified vulnerable release built and installed
  with `adb install -t` on API 34, but no attack was run against it.

## Not covered in v1

| Attack surface | Threat (SPEC section 2) | Why not covered | Limitation |
|---|---|---|---|
| An Intent held inside a custom `Parcelable` or `Serializable` extra | 1 (intent redirection) | Object fields are opaque to ShezGuard; only framework containers are searched | `docs/LIMITATIONS.md` L26 |
| `ClipData` of the incoming intent (including `ClipData.Item` intents and URIs) | 1 | Only extras are inspected; ClipData is checked only on nested intents, by `IntentSanitizer` | L26 |
| The selector of the incoming intent (`Intent.getSelector()`) | 1 | Not inspected | L26 |
| URI-permission grant flags (`FLAG_GRANT_*_URI_PERMISSION`) on the incoming intent | 1 | Flags are not inspected; on nested intents they depend on the developer's `IntentSanitizer` | L26 |
