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
| R3 | 2026-11-13 | Pixel_8 AVD, same image as R1 (`UE1A.230829.036.A4`, WebView 137.0.7151.116) | 14 (API 34) | `1.0-vulnerable` (debug) | step 12 working tree on top of `70c6c8e`: `t5` and `t5 gadget` re-run (decision 2), `t2d copies`, benign controls |
| R4 | 2026-11-13 | Pixel_4 AVD, same image as R2 (`QSR1.211112.011`, WebView 91.0.4472.114) | 10 (API 29) | `1.0-vulnerable` (debug) | as R3: `t5`, `t5 gadget`, benign controls |
| R5 | 2026-11-13 | as R3 | 14 (API 34) | `1.0-protected` (debug, `LogcatAuditSink` on) | every attack script and every benign control |
| R6 | 2026-11-13 | as R4 | 10 (API 29) | `1.0-protected` (debug) | `t4`, `t5`, `t5 gadget`, benign controls |
| R7 | 2026-11-13 | as R3 | 14 (API 34) | `1.0-protected` (`minified`: R8, debug key, test-only, `LogcatAuditSink` on), final keep rule | every attack script and every benign control |
| R7a | 2026-11-13 | as R3 | 14 (API 34) | `1.0-protected` (`minified`), **first** keep rule for `LegacyProfile` | `t5 gadget` only (R8 section) |
| R7b | 2026-11-13 | as R3 | 14 (API 34) | `1.0-vulnerable` (`minified`), first keep rule | `gadget` sent by hand, not a script (R8 section) |

R1 and R2 used the final step 11 scripts (logs bounded by time, `am start` without `-W`; see
`scripts/attacks/README.md`). An earlier API 29 attempt was discarded: `logcat -c` does not clear on
that image, so evidence from one script leaked into the next. It is not recorded here.

## Results (step 11: vulnerable flavor)

The "Protected (step 12)" column below is superseded by the step 12 section, which has one column per
API level and build.

| Attack | Threat | Script | Entry point | Vulnerable, API 34 (R1) | Vulnerable, API 29 (R2) | Protected (step 12) | Evidence |
|---|---|---|---|---|---|---|---|
| Nested Intent extra forwarded to a non-exported activity | 1 | `t1_nested_intent_redirect.sh` | `ForwardActivity` | EXPLOITED | EXPLOITED | see step 12 | Both: control (the shell starts `InternalAdminActivity` directly) failed with `SecurityException ... not exported`; via `ForwardActivity`, sent by `:attacker`: `CANARY-ADMIN-REACHED`. |
| SQL injection via `?q=` | 2 | `t2a_sql_injection.sh` | `SearchActivity` | EXPLOITED | EXPLOITED | see step 12 | Both: `q=x' OR hidden=1 --` returned both `CANARY-HIDDEN-ROW-*` rows. |
| Attacker URL loaded into a WebView via `?url=` | 2 | `t2b_webview_url.sh` | `PreviewActivity` | EXPLOITED | EXPLOITED | see step 12 | Both: `file:///data/user/0/com.shezguard.router/files/secret.txt` showed `CANARY-SECRET-7f3a`; a `data:` page ran its script (`console: CANARY-JS-42`). |
| Path traversal via `?name=` | 2 | `t2c_path_traversal.sh` | `FileViewerActivity` | EXPLOITED | EXPLOITED | see step 12 | Both: `name=../secret.txt` read `CANARY-SECRET-7f3a`. |
| Oversized extras (denial of service) | 2 | `t2d_oversized_extra.sh` | `NoteActivity` | EXPLOITED (crash) | EXPLOITED (crash) | see step 12 | 64 000-character `note`, `copies=20000`: `OutOfMemoryError` in `NoteActivity.handle` (API 34: "Failed to allocate a 1280000016 byte allocation"; API 29: "a 2560000016 byte allocation"). |
| Open redirect via `?next=` | 3 | `t3_open_redirect.sh` | `RedirectActivity` | EXPLOITED | EXPLOITED | see step 12 | Both: `next=https://attacker.invalid/login` opened `:attacker`'s `LandingActivity` (`CANARY-REDIRECT-LANDED on attacker.invalid`). Simulated user choice of `:attacker` for `attacker.invalid` (API 34: `pm set-app-links-user-selection`; API 29: `pm set-app-link ... always`). |
| Deep link hijacking (custom scheme; https without `autoVerify`) | 4 | `t4_link_hijack.sh` | `LinkActivity` | EXPLOITED | EXPLOITED | **not prevented at runtime; detected at build time (step 13)** | Both: `cmd package query-activities` lists `com.shezguard.attacker/.HijackActivity` as a handler of `shezdemo://login` (2 handlers) and of `https://shezguard.example/login` (3, with Chrome). API 34 `pm get-app-links --user 0`: `shezguard.example` not verified ("Disabled"). With the user's choice of `:attacker` simulated, a login link opened without a target package went to `:attacker`, which logged `HIJACKED ... token=CANARY-TOKEN-…`. |
| Serializable of an unknown class (malformed Bundle) | 5 | `t5_malformed_bundle.sh` | `ProfileActivity` | EXPLOITED (crash) | EXPLOITED (crash) | see step 12 | Both crash in `Intent.getSerializableExtra` called from `ProfileActivity.handle`. API 34: `BadParcelableException`, one lazy value (`BaseBundle.unwrapLazyValueFromMapLocked`). API 29: `RuntimeException: Parcelable encountered ClassNotFoundException`, while the whole Bundle is unparcelled (`BaseBundle.unparcel` → `initializeFromParcelLocked`). |
| Deserialisation gadget (`LegacyProfile.readObject`) | 5 (5b) | `t5_malformed_bundle.sh gadget` | `ProfileActivity` | EXPLOITED | EXPLOITED | **not prevented** (see note) | Both: `CANARY-GADGET-24 side effect ran during deserialisation`. |
| Encoding evasion of a manual `..` check | 6 | `t6_encoding_manual_check.sh` | `ManualCheckActivity` | EXPLOITED | EXPLOITED | see step 12 | Both: control (raw `../secret.txt`) was rejected by the manual check; `%2e%2e%2fsecret.txt` and `%252e%252e%252fsecret.txt` passed it and read `CANARY-SECRET-7f3a`. |

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
- **`t2d` uses a large `note`.** A small note with a very large `copies` (an int) also exhausts
  the heap; ShezGuard's extras rule bounds strings and arrays, not int values. Run in step 12 as
  `t2d copies` (EXPLOITED in both flavors; L38).
- Release builds: R1 and R2 used debug builds. A minified vulnerable release built and installed
  with `adb install -t` on API 34, but no attack was run against it.

## Step 12: predictions (written before any protected-flavor run)

Written on 2026-11-13, **before any script was run against the `protected` flavor**, and committed on
its own so that the predictions cannot be adjusted after the fact (commit `70c6c8e`). The result columns said "pending";
they were filled in afterwards from runs R3–R7, without changing any prediction text. An entry such as
`NOT_EXPLOITED (R5): **blocked**` gives the script's RESULT line and the run, then its interpretation.
Step 12 fills them in from the script output and explains every difference from the prediction. A row
is marked blocked only if a script shows it, and every blocked row must cite a library test that proves it.

Prediction values:
- **blocked**: ShezGuard returns Block, so the entry point's code does not run. Script: `NOT_EXPLOITED`.
- **sanitized**: ShezGuard returns Sanitize, the attack payload is removed, and the entry point runs on
  the cleaned intent. Script: `NOT_EXPLOITED`.
- **not prevented**: the attack works in the protected flavor too. Script: `EXPLOITED`.

### Policy the predictions assume (approved proposal, `docs/RESPONSE.md`)

These settings apply to every entry point unless a row says otherwise:
- library default limits (URI 2048 characters, parameter 256);
- no fragment, no non-default port, host `shezguard.example` matched exactly;
- `Caller.Any`;
- no extras allowed (an extra that is present is removed, which gives Sanitize);
- `Nested.Deny`.

| Entry point | Activity | Policy |
|---|---|---|
| `forward` | `ForwardActivity` | Data `Forbidden`. `nestedIntents(AllowSanitized("next"))`, with an `IntentSanitizer` that allows only the component `SearchActivity`, action `VIEW`, category `BROWSABLE` and data with authority `shezguard.example`. `FileViewerActivity` is **not** allowed: no feature of the demo forwards to it (the only forward target is search), so allowing it would be speculative (author condition 1). |
| `search` | `SearchActivity` | `https`, path `exact("/search")`. `q`: `string(PRINTABLE_ASCII, maxLength = 64)`, because a search box must accept spaces and `'`. `unknownParams(Drop)`. |
| `preview` | `PreviewActivity` | `https`, `exact("/preview")`. `url`: required, `url { allowSchemes("https"); allowHosts("shezguard.example") }`. `unknownParams(Block)`. |
| `file` | `FileViewerActivity` | `https`, `exact("/file")`. `name`: required, `string(PRINTABLE_ASCII, 64)`. `SLUG` rejects the `.` in `readme.txt`, and no class admits `.` but rejects `..` (author decision 1, L37). `unknownParams(Drop)`. |
| `note` | `NoteActivity` | Data `Forbidden`. Extras: `note` `STRING`, `copies` `INT`, `maxStringLength(2000)`. |
| `redirect` | `RedirectActivity` | `https`, `exact("/redirect")`. `next`: required, `url { https; shezguard.example }`. `unknownParams(Block)`. |
| `login` | `LinkActivity` | Schemes `https` and `shezdemo`; hosts `shezguard.example` and `login`; `anyPath()`. `token`: required, `string(SLUG, 64)`. `unknownParams(Block)`. The policy cannot bind a host to a scheme, so `shezdemo://shezguard.example` and `https://login` are also accepted (to be recorded as a limitation). `requireVerifiedDomain()` is not allowed together with a custom scheme (DSL rule 15). |
| `profile` | `ProfileActivity` | Data `Forbidden`. No extras: a Serializable cannot be allow-listed (L6). |
| `manual` | `ManualCheckActivity` | Same rule as `file`: `https`, `exact("/manual")`, `name` `string(PRINTABLE_ASCII, 64)`, `unknownParams(Drop)`. |
| (exempt) | `MainActivity` | `@GuardedEntryPoint(exempt = true)`. It does not call the guard and reads no input. |

The vulnerable flavor has `:shezguard-core` on its classpath and carries the same `@GuardedEntryPoint`
annotations, but never calls the library. Its `EntryGuard` is a pass-through.

### Attacks

Column notes:
- Vulnerable results come from R1 and R2 (step 11).
- `t2d copies` is a new mode of `t2d`, not run yet in either flavor.
- The protected flavor is run on API 34 for every row, and on API 29 only for t4, t5 and 5b (per the
  author's instructions).
- "Minified" is the `protectedMinified` build (R8) on API 34.

| Threat | Attack (script) | Vuln. 34 | Vuln. 29 | **Prediction (protected)** and reason | Prot. 34 | Prot. 29 | Minified 34 | Codes seen | Library test | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Nested Intent to non-exported `InternalAdminActivity` (`t1_nested_intent_redirect.sh`) | EXPLOITED | EXPLOITED | **blocked**, `NESTED_INTENT_DENIED` on `extra:next`. The sanitizer does not allow `InternalAdminActivity`, so `IntentSanitizer` rewrites the component to `android/java.lang.Void`. ShezGuard treats that rewrite as denial, not removal. | NOT_EXPLOITED (R5): **blocked** | n/a | NOT_EXPLOITED (R7) | `BLOCK` `NESTED_INTENT_DENIED@extra:next`; no `CANARY-ADMIN-REACHED` | `NestedIntentTest.blocksNestedIntentWhoseComponentIntentSanitizerRewrites` (exists) |  |
| 2 | SQL injection `q=x' OR hidden=1 --` (`t2a_sql_injection.sh`) | EXPLOITED | EXPLOITED | **not prevented** (Allow, no violation). The decoded value is valid `PRINTABLE_ASCII` and 18 characters long. Parameter validation does not replace a parameterised query. | EXPLOITED (R5): **not prevented** | n/a | EXPLOITED (R7) | `ALLOW`, no violation; `results=[CANARY-HIDDEN-ROW-1 …, CANARY-HIDDEN-ROW-2 …]` | none (not a block). `DemoPolicyTest.notPreventedAttackLinksAreAllowed` replays the Allow. |  |
| 2 | WebView `url=file:///…/secret.txt` and `url=data:text/html,<script>…` (`t2b_webview_url.sh`) | EXPLOITED | EXPLOITED | **blocked**, `PARAM_URL_NOT_ALLOWED` on `param:url`, for both payloads. Neither is `https` on the allowed host. | NOT_EXPLOITED (R5): **blocked** | n/a | NOT_EXPLOITED (R7) | `BLOCK` `PARAM_URL_NOT_ALLOWED@param:url`, once per payload (2) | `UriPolicyValidatorTest.blocksFileUrlInWebViewParam` (**added**, `file:`) and `blocksJavascriptAndDataUrls` (`data:`); `DemoPolicyTest.blockedAttackLinksGiveTheCodesSeenOnTheDevice` |  |
| 2 | Path traversal `name=../secret.txt` (`t2c_path_traversal.sh`) | EXPLOITED | EXPLOITED | **not prevented** (Allow). `../secret.txt` is valid `PRINTABLE_ASCII`. The `..` checks apply to path segments, not to query values. | EXPLOITED (R5): **not prevented** | n/a | EXPLOITED (R7) | `ALLOW`, no violation; `file content: CANARY-SECRET-7f3a` | none (not a block). L37: `printableAsciiFileNameAcceptsTraversalValues`; mitigation for a fixed file set: `blocksPathTraversalInOneOfFileName` (**added**) | L37 (to be written): no file-name class. |
| 2 | Oversized `note` (64 000 characters), `copies=20000` (`t2d_oversized_extra.sh`) | EXPLOITED (crash) | EXPLOITED (crash) | **blocked**, `EXTRA_TOO_LARGE` on `extra:note`. 64 000 > 2000. | NOT_EXPLOITED (R5): **blocked** | n/a | NOT_EXPLOITED (R7) | `BLOCK` `EXTRA_TOO_LARGE@extra:note`; no crash | `ExtrasEvaluateTest.blocksOversizedStringExtra`; `DemoPolicyTest.noteExtras` | |
| 2 | Short `note` (1000 characters), `copies=2000000` (`t2d_oversized_extra.sh copies`, new mode) | EXPLOITED (R3), `OutOfMemoryError` (2 000 000 016-byte allocation) | not run | **not prevented** (Allow), crash with `OutOfMemoryError`. Both extras have the allowed type and size; an `INT` value cannot be range-limited. The vulnerable flavor is predicted EXPLOITED too (to be run on API 34). | EXPLOITED (R5): **not prevented** | n/a | EXPLOITED (R7) | `ALLOW`, no violation; then `OutOfMemoryError` in `NoteActivity` | none (not a block). `DemoPolicyTest.noteExtras` replays the Allow. | L38 (to be written). |
| 3 | Open redirect `next=https://attacker.invalid/login` (`t3_open_redirect.sh`) | EXPLOITED | EXPLOITED | **blocked**, `PARAM_URL_NOT_ALLOWED` on `param:next`. The host is not allowed. | NOT_EXPLOITED (R5): **blocked** | n/a | NOT_EXPLOITED (R7) | `BLOCK` `PARAM_URL_NOT_ALLOWED@param:next`; no `CANARY-REDIRECT-LANDED` | `UriPolicyValidatorTest.blocksOpenRedirectToUnlistedHost`; `DemoPolicyTest.blockedAttackLinksGiveTheCodesSeenOnTheDevice` |  |
| 4 | Link hijacking (`t4_link_hijack.sh`) | EXPLOITED | EXPLOITED | **not prevented**, on both APIs. The OS sends the link to `:attacker`, so `LinkActivity` (and ShezGuard) never run and no audit line is expected. | EXPLOITED (R5): **not prevented** | EXPLOITED (R6): **not prevented** | EXPLOITED (R7) | none: no `ShezGuard` line. `LinkActivity` was never started; `:attacker` logged `HIJACKED … token=CANARY-TOKEN-…` | none | Build-time check in step 13; L3, L32. |
| 5 | Serializable of an unknown class (`t5_malformed_bundle.sh`) | EXPLOITED (crash) | EXPLOITED (crash) | **blocked, no crash**, `EXTRAS_UNPARCEL_FAILED`. API 34: on `extra:profile` (one lazy value fails). API 29: on the whole extras (`keySet()` unparcels everything). The exception is caught inside ShezGuard. | NOT_EXPLOITED (R5): **blocked, no crash** | NOT_EXPLOITED (R6): **blocked, no crash** | NOT_EXPLOITED (R7) | API 34: `BLOCK` `EXTRAS_UNPARCEL_FAILED@extra:<undeclared>`, `EXTRA_NOT_ALLOWED@extra:<undeclared>`. API 29: `BLOCK` `EXTRAS_UNPARCEL_FAILED@extras`. No entry in the crash buffer. | `SerializableExtrasTest.blocksSerializableOfUnknownClassWithoutCrashing` (**added**; SDK 24, 29, 34) |  |
| 5 (5b) | Gadget `LegacyProfile.readObject` (`t5_malformed_bundle.sh gadget`) | EXPLOITED | EXPLOITED | **not prevented**, on both APIs. ShezGuard reads every extra (to find nested intents), so `readObject` runs inside ShezGuard before any decision. The decision is then **Sanitize** with `EXTRA_NOT_ALLOWED` on `extra:profile`, and the app shows `profile=none`. | EXPLOITED (R5): **not prevented** | EXPLOITED (R6): **not prevented** | EXPLOITED (R7), with the final keep rule. With the first keep rule: native crash (R7a), see R8 section. | `SANITIZE` `EXTRA_NOT_ALLOWED@extra:<undeclared>`; `CANARY-GADGET-24` logged; the app showed `profile=none` | `SerializableExtrasTest.gadgetReadObjectRunsDuringExtrasInspection` (**added**; documents the limitation, not a block) | L1, L27. Needs `appFilesDir` set in `DemoApp` (decision 2) and R8 keep rules for `LegacyProfile` in the minified build. |
| 6 | Manual check vs encoding (`t6_encoding_manual_check.sh`), 3 payloads | EXPLOITED | EXPLOITED | Raw `../secret.txt`: ShezGuard **allows** it, then the manual check rejects it. `%2e%2e%2fsecret.txt`: **not prevented** (Allow, decodes once to `../secret.txt`; needless-escape detection applies only to the path). `%252e%252e%252fsecret.txt`: **blocked**, `URI_DOUBLE_ENCODING` on `uri.query`. The script as a whole is predicted **EXPLOITED** (the second payload). | EXPLOITED (R5): as predicted, payload by payload | n/a | EXPLOITED (R7), same per payload | raw `../`: `ALLOW`, then `rejected by the manual check`; `%2e%2e%2f`: `ALLOW`, `CANARY-SECRET-7f3a`; `%252e…`: `BLOCK` `URI_DOUBLE_ENCODING@uri.query` | `UriCanonicalizerTest.blocksDoubleEncodingInQueryValue` (third payload only); `DemoPolicyTest.blockedAttackLinksGiveTheCodesSeenOnTheDevice`. Not prevented (second payload): `notPreventedAttackLinksAreAllowed`. |  |

Vulnerable re-runs after decision 2: `LegacyProfile.appFilesDir` moves to `DemoApp.onCreate`, so `t5` and
`t5 gadget` are run again on the vulnerable flavor. The prediction is that nothing changes on API 34 or
API 29 (crash; `CANARY-GADGET-24`).

**Results (R3, R4): unchanged.**
- `t5`: EXPLOITED (crash) on both APIs, with the same exceptions as R1/R2: API 34
  `BadParcelableException`, API 29 `RuntimeException: Parcelable encountered ClassNotFoundException
  reading a Serializable object (name = com.shezguard.attacker.AttackActivity$UnknownPayload)`.
- `t5 gadget`: EXPLOITED on both APIs, `CANARY-GADGET-24 side effect ran during deserialisation`.

These runs were made twice, before and after the script fix for native crashes (R8 section), with the
same results.

### R8 (`protectedMinified`, API 34)

Every row above is predicted to give the same RESULT line as the unminified protected build, and every
`ShezGuard` audit line is predicted to name its entry point (`ep=<name>`), with **no**
`ENTRY_POINT_NOT_ANNOTATED` or `<unannotated>`. The prediction relies on two things:
- the library's consumer rules (L36), which keep `@GuardedEntryPoint`;
- the app's Serializable keep rules for `LegacyProfile`. Without them, 5b would turn into the
  unknown-class case.

**Results (R7, with the final keep rule): as predicted.**
- **Same RESULT for every script run.** All 11 attack runs and 10 benign runs (21 in total) match the
  unminified protected build on API 34 (R5).
- **26 `ShezGuard` audit lines, each naming its entry point** (`ep=forward`, `search`, `preview`,
  `file`, `note`, `redirect`, `login`, `profile`, `manual`). No `ENTRY_POINT_NOT_ANNOTATED` and no
  `<unannotated>` (0 matches). The codes match R5 line for line.
- **Static check:** `apkanalyzer dex code` shows `.annotation runtime Lcom/shezguard/core/GuardedEntryPoint;`
  with the right `name` on all nine demo activities, and `exempt = true` on `MainActivity`. In
  `mapping.txt`, `GuardedEntryPoint` and the activities keep their names; `DemoPolicy`, `EntryGuard` and
  the library internals are renamed. The minified APK's manifest has `android:testOnly="true"` and is
  not debuggable.

**Difference from the prediction: the first keep rule was not enough (R7a).** The prediction assumed
"the app's Serializable keep rules". The first version used the usual form (`-keepnames` plus
`-keepclassmembers { serialVersionUID; readObject; <fields>; }`). Because the app never constructs a
`LegacyProfile`, R8 still made the class **abstract** and removed `readObject` and the `name` field.
- **R7a, protected minified with that rule, `t5 gadget`:** the app process **crashed natively**
  (`SIGSEGV`, `SEGV_ACCERR`) during `DemoActivity.onCreate`. `retrace` places the Java frames in
  ShezGuard's extras inspection (`AndroidExtras` value classification ← `ShezGuard.decide` ←
  `ActivityGuard.onCreate`); the tombstone gives dex pcs, so the innermost frame is approximate.
- **The script missed it.** `t5_malformed_bundle.sh gadget` printed `RESULT: NOT_EXPLOITED`, because
  `crash_log` matched only Java crashes. Fixed in `_common.sh` (it now also matches the tombstone line
  `>>> com.shezguard.router <<<`). Re-run against the same APK: `RESULT: EXPLOITED`, with the tombstone
  as evidence.
- **R7b, vulnerable minified with the same rule, `gadget` sent by hand** (`am start … -e attack gadget`;
  not a script run): no crash, but `ProfileActivity`'s `"profile=$profile"` logged lines of raw binary
  memory. So the fault is not specific to ShezGuard; any code touching the object misbehaves.
- **Fix:** `-keep class com.shezguard.router.demo.LegacyProfile { *; }` (`app/proguard-rules.pro`).
  The class then stays `final` and concrete, with `readObject`, `name` and its constructor, and R7
  matches R5. Not a ShezGuard bug: an app keep-rule issue whose effect ShezGuard cannot catch
  (`docs/LIMITATIONS.md` L40, `docs/PAPER_NOTES.md` N15).
- **Consequence for the earlier runs:** every step 12 result recorded here (R3–R7) comes from runs
  made after the script fix. The protected debug runs made before the fix gave the same RESULT lines.

### Benign controls

Script result values: `WORKS`, `BROKEN`, `INCONCLUSIVE`. Every benign script is run on both flavors on
API 34 and API 29, and on `protectedMinified` on API 34.

| Script | Legitimate request | Prediction, vulnerable | Prediction, protected (and minified) | Results |
|---|---|---|---|---|
| `b1_forward.sh` | Helper app (`benign_forward`). `next` is VIEW `https://shezguard.example/search?q=mug`, targeting `SearchActivity`. | WORKS | WORKS. **Sanitize** (`NESTED_INTENT_SANITIZED`, always for an allowed nested intent): the app forwards the sanitizer's output. `SearchActivity` is then Allowed by its own guard and returns `results=[Blue mug]`. | WORKS on all five (vulnerable 34 and 29; protected 34 and 29: `SANITIZE ep=forward [NESTED_INTENT_SANITIZED@extra:next]`, then `ALLOW ep=search`; minified 34: the same) |
| `b2a_search.sh` | `/search?q=blue%20mug` | WORKS | WORKS, Allow | WORKS on all five; protected: `ALLOW ep=search` |
| `b2b_preview.sh` | `/preview?url=https%3A%2F%2Fshezguard.example%2Fhelp` | WORKS | WORKS, Allow. The page itself fails to load in both flavors, because the app has no INTERNET permission. | WORKS on all five; protected: `ALLOW ep=preview` (`page text: ""` in both flavors: no network) |
| `b2c_file.sh` | `/file?name=readme.txt` | WORKS | WORKS, Allow | WORKS on all five; protected: `ALLOW ep=file` |
| `b2d_note.sh` | `note="Buy milk"`, `copies=2` | WORKS | WORKS, Allow | WORKS on all five; protected: `ALLOW ep=note` |
| `b3_redirect.sh` | `/redirect?next=https%3A%2F%2Fshezguard.example%2Fhelp` | WORKS | WORKS, Allow | WORKS on all five; protected: `ALLOW ep=redirect`. Evidence: the app's own `START u0 {act=android.intent.action.VIEW dat=https://shezguard.example/... cmp=com.android.chrome/...}` |
| `b4_login.sh` | `https://shezguard.example/login?token=abc123` and `shezdemo://login?token=abc123`, explicit package | WORKS | WORKS, Allow for both. Least certain: the custom-scheme URI has an empty path, and this is the first device run of a non-http scheme. | WORKS on all five, for both the https and the custom-scheme link; protected: `ALLOW ep=login` for each |
| `b5_profile.sh` | Helper app (`benign_profile`). `profile` is `LegacyProfile("alice")`. | WORKS | **BROKEN, by design**: Sanitize with `EXTRA_NOT_ALLOWED`, and the app shows `profile=none`. A Serializable extra cannot be allow-listed (L6), and `readObject` still runs (5b). | Vulnerable: WORKS (34, 29), and `CANARY-GADGET-24` ran too (the same `readObject`). Protected 34, 29 and minified 34: **BROKEN** (`SANITIZE ep=profile [EXTRA_NOT_ALLOWED@extra:<undeclared>]`, `profile=none`), and `readObject` still ran |
| `b6_manual.sh` | `/manual?name=readme.txt` | WORKS | WORKS, Allow | WORKS on all five; protected: `ALLOW ep=manual` |

### Comparison baselines (SPEC 10.3)

- **Manual validation:** `ManualCheckActivity`, the vulnerable flavor's `t6` results (step 11).
- **IntentSanitizer alone:** a Robolectric test (`IntentSanitizerBaselineTest`, to be written). For each
  attack it applies the tightest allow-list `IntentSanitizer` can express. Every allow-list will be
  listed in full here.
  - **Data:** the boundary is `allowData` / `allowDataWithAuthority` predicates on scheme, authority
    and path. A predicate that parses query parameters is hand-written validation, which is the manual
    baseline, not `IntentSanitizer`.
  - **Extras:** predicates that check type and length, mirroring the ShezGuard extras rule.

| Attack | Predicted with IntentSanitizer alone | Reason |
|---|---|---|
| t1 | prevented (if the developer also sanitizes the nested intent) | `allowComponent(SearchActivity)` rejects `InternalAdminActivity` |
| t2a, t2b, t2c, t3, t6 (all payloads) | not prevented | The data predicate sees only scheme, host and path. Query content and its encoding are not checked. |
| t2d (large note) | prevented | A length predicate on `note` removes the extra |
| t2d copies | not prevented by the tightest *type* rule. A value predicate `copies <= N` is expressible, so this row will be recorded as "prevented only with a value predicate". | |
| t4 | not applicable (no app code runs) | |
| t5 | not prevented: the unparcel exception is expected to propagate out of `sanitize`, so the app crashes | |
| 5b | not prevented: reading the extra runs `readObject` | |

**Results** (`shezguard-core/.../comparison/IntentSanitizerBaselineTest`, Robolectric SDK 29 and 34, both
SDKs identical unless stated): **as predicted for every row.** Each allow-list also lets the matching
benign request through unchanged, so none is tighter than the feature needs.

The allow-lists, in full (`PKG` = `com.shezguard.router`, `HOST` = `shezguard.example`):
- **Deep links** (`search`, `preview`, `file`, `redirect`, `manual`): `allowComponent(PKG/.demo.<Activity>)`,
  `allowAction(VIEW)`, `allowCategory(BROWSABLE)`,
  `allowData { scheme == "https" && host == HOST && path == "/<search|preview|file|redirect|manual>" }`.
  Nothing else.
- **`forward`, outer intent:** `allowComponent(ForwardActivity)` and `allowExtra("next", Intent::class.java)`.
- **`forward`, nested intent, sanitized again before use** (the same rule as `DemoPolicy`):
  `allowComponent(SearchActivity)`, `allowAction(VIEW)`, `allowCategory(BROWSABLE)`,
  `allowDataWithAuthority(HOST)`.
- **`note`:** `allowComponent(NoteActivity)`, `allowExtra("note") { it is String && it.length <= 2000 }`,
  and `allowExtra("copies") { it is Int }` (type rule) or `{ it is Int && it in 1..100 }` (value rule).
- **`profile`:** `allowComponent(ProfileActivity)` and no extras. Tightest, because a Serializable
  cannot be checked without deserialising it.

| Attack | None (vulnerable) | Manual validation (`ManualCheckActivity`) | IntentSanitizer alone (test) | ShezGuard (scripts, this step) |
|---|---|---|---|---|
| t1 nested intent | EXPLOITED | n/a | **prevented**: nested component rewritten to `android/java.lang.Void`, 1 penalty (needs the second `sanitize` call on the nested intent) | **blocked** (`NESTED_INTENT_DENIED`) |
| t2a SQL injection | EXPLOITED | n/a | not prevented: data passes unchanged, 0 penalties | not prevented |
| t2b `file:` / `data:` URL | EXPLOITED | n/a | not prevented (both payloads) | **blocked** (`PARAM_URL_NOT_ALLOWED`) |
| t2c traversal | EXPLOITED | n/a | not prevented | not prevented (L37) |
| t2d large note | EXPLOITED (crash) | n/a | **prevented**: `note` removed, 1 penalty | **blocked** (`EXTRA_TOO_LARGE`) |
| t2d huge `copies` | EXPLOITED (crash) | n/a | type rule: not prevented. Value rule `1..100`: **prevented** (`copies` removed) | not prevented (L38). **IntentSanitizer is more expressive here.** |
| t3 open redirect | EXPLOITED | n/a | not prevented | **blocked** (`PARAM_URL_NOT_ALLOWED`) |
| t4 hijack | EXPLOITED | n/a | n/a (no app code runs) | not prevented |
| t5 unknown class | EXPLOITED (crash) | n/a | not prevented: `sanitize` throws (API 34 `BadParcelableException`, API 29 `RuntimeException`); uncaught, the app crashes | **blocked, no crash** (`EXTRAS_UNPARCEL_FAILED`) |
| 5b gadget | EXPLOITED | n/a | not prevented: `readObject` ran inside `sanitize`, then the extra was removed | not prevented: `readObject` ran inside ShezGuard, then the extra was removed (Sanitize) |
| t6 raw `../` | EXPLOITED | **rejected** | not prevented | not prevented by ShezGuard; the manual check still rejects it |
| t6 `%2e%2e%2f` | EXPLOITED | **bypassed** | not prevented | not prevented (decodes once to `../`, L37) |
| t6 `%252e%252e%252f` | EXPLOITED | **bypassed** | not prevented | **blocked** (`URI_DOUBLE_ENCODING`) |

Reading the comparison:
- **What IntentSanitizer cannot see:** query parameter content and its encoding (t2a, t2b, t2c, t3,
  t6). Its `allowData` predicate *could* parse the query, but then it is hand-written validation with
  the same pitfalls as `ManualCheckActivity`.
- **Where IntentSanitizer is enough, or stronger:**
  - nested intents (t1), when the developer remembers to sanitize the nested intent too;
  - extras size (t2d);
  - numeric value bounds (`copies`), which ShezGuard cannot express (L38).
- **Where ShezGuard adds something:**
  - URL-typed parameters (t2b, t3);
  - double encoding (t6);
  - unparcelling failures without a crash (t5).
- **Neither prevents** SQL injection through a printable value (t2a), traversal through a printable
  file name (t2c, t6 single-encoded), the deserialisation gadget (5b) or link hijacking (t4).
- **Limits of this comparison:** the IntentSanitizer column is Robolectric only, not a device run; the
  allow-lists are the author of this step's best reading of "tightest"; manual validation exists for
  one entry point only.

### Differences between predictions and results

Every RESULT line matched its prediction:
- all 11 attack rows on protected API 34 (R5) and minified API 34 (R7), plus t4, t5 and 5b on protected
  API 29 (R6);
- the 10 benign runs on each of the 5 flavor/API combinations (R3–R7);
- every case of the IntentSanitizer baseline. The differences are in details:
1. **`t5`, API 34: two codes, not one.** The prediction named `EXTRAS_UNPARCEL_FAILED` only. The decision
   also has `EXTRA_NOT_ALLOWED` for the same key: the value failed to unparcel *and* the key is not in
   the allow-list. Both are collected, as SPEC 5 requires (all violations, not the first). API 29 has
   one code, because the whole Bundle fails at `keySet()` and no key is known.
2. **The field is logged as `extra:<undeclared>`, not `extra:profile`.** This is the step 9 redaction:
   a key the policy does not declare is never written into an audit event. The prediction's wording was
   wrong; the behaviour is as designed.
3. **R8: the predicted keep rule was not enough** (R8 section, R7a). The prediction ("same as
   unminified") held only after the keep rule was strengthened. With the usual Serializable rules the
   minified app crashed natively inside ShezGuard's extras inspection, and the step 11 scripts did not
   detect native crashes. Both are fixed in the app and the scripts, not in the library (L40, N15).
4. **`b4_login` (the least certain prediction) worked** for the custom scheme with an empty path.

No library change was made in step 12. The library *tests* added are listed in the rows above.

## Not covered in v1

**Shown not prevented in step 12** (demo app, realistic policy; details in the rows above):

| Attack | Why ShezGuard does not prevent it | Limitation |
|---|---|---|
| SQL injection through a search term (`t2a`) | A search box must accept `'` and spaces; validation does not replace parameterised SQL | `CharClass` KDoc |
| Path traversal through a file name (`t2c`, `t6` single-encoded) | No parameter type admits `readme.txt` but rejects `../`; `..` checks apply to path segments only | L37 |
| Huge numeric extra (`t2d copies`) | `INT` extras are type-checked, not range-checked | L38 |
| Deep link hijacking (`t4`) | The OS routes the link before any app code runs | L3, L32; build-time check in step 13 |
| Deserialisation gadget (5b) | ShezGuard deserialises every extra to look for nested intents | L1, L27 |
| A legitimate Serializable extra (`b5`, a benign control) | Cannot be allow-listed; the feature breaks under ShezGuard | L6 |
| Native crash while inspecting an extra (R7a) | A signal cannot be caught | L40 |

**Not covered by design:**

| Attack surface | Threat (SPEC section 2) | Why not covered | Limitation |
|---|---|---|---|
| An Intent held inside a custom `Parcelable` or `Serializable` extra | 1 (intent redirection) | Object fields are opaque to ShezGuard; only framework containers are searched | `docs/LIMITATIONS.md` L26 |
| `ClipData` of the incoming intent (including `ClipData.Item` intents and URIs) | 1 | Only extras are inspected; ClipData is checked only on nested intents, by `IntentSanitizer` | L26 |
| The selector of the incoming intent (`Intent.getSelector()`) | 1 | Not inspected | L26 |
| URI-permission grant flags (`FLAG_GRANT_*_URI_PERMISSION`) on the incoming intent | 1 | Flags are not inspected; on nested intents they depend on the developer's `IntentSanitizer` | L26 |
