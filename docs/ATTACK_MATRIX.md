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

## Step 12: predictions (written before any protected-flavor run)

Written on 2026-11-13, **before any script was run against the `protected` flavor**, and committed on
its own so that the predictions cannot be adjusted after the fact. The result columns say "pending".
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
| 1 | Nested Intent to non-exported `InternalAdminActivity` (`t1_nested_intent_redirect.sh`) | EXPLOITED | EXPLOITED | **blocked**, `NESTED_INTENT_DENIED` on `extra:next`. The sanitizer does not allow `InternalAdminActivity`, so `IntentSanitizer` rewrites the component to `android/java.lang.Void`. ShezGuard treats that rewrite as denial, not removal. | pending | n/a | pending | pending | `NestedIntentTest.blocksNestedIntentWhoseComponentIntentSanitizerRewrites` (exists) | |
| 2 | SQL injection `q=x' OR hidden=1 --` (`t2a_sql_injection.sh`) | EXPLOITED | EXPLOITED | **not prevented** (Allow, no violation). The decoded value is valid `PRINTABLE_ASCII` and 18 characters long. Parameter validation does not replace a parameterised query. | pending | n/a | pending | pending | none (not a block). `CharClassTest` documents that `PRINTABLE_ASCII` accepts `it's`. | |
| 2 | WebView `url=file:///…/secret.txt` and `url=data:text/html,<script>…` (`t2b_webview_url.sh`) | EXPLOITED | EXPLOITED | **blocked**, `PARAM_URL_NOT_ALLOWED` on `param:url`, for both payloads. Neither is `https` on the allowed host. | pending | n/a | pending | pending | `UriPolicyValidatorTest.blocksJavascriptAndDataUrls` (exists; covers `data:`). **To add:** `blocksFileUrlInWebViewParam`, because `file:` is not covered. | |
| 2 | Path traversal `name=../secret.txt` (`t2c_path_traversal.sh`) | EXPLOITED | EXPLOITED | **not prevented** (Allow). `../secret.txt` is valid `PRINTABLE_ASCII`. The `..` checks apply to path segments, not to query values. | pending | n/a | pending | pending | none (not a block) | L37 (to be written): no file-name class. |
| 2 | Oversized `note` (64 000 characters), `copies=20000` (`t2d_oversized_extra.sh`) | EXPLOITED (crash) | EXPLOITED (crash) | **blocked**, `EXTRA_TOO_LARGE` on `extra:note`. 64 000 > 2000. | pending | n/a | pending | pending | `ExtrasEvaluateTest.blocksOversizedStringExtra` (exists) | |
| 2 | Short `note` (1000 characters), `copies=2000000` (`t2d_oversized_extra.sh copies`, new mode) | not run | not run | **not prevented** (Allow), crash with `OutOfMemoryError`. Both extras have the allowed type and size; an `INT` value cannot be range-limited. The vulnerable flavor is predicted EXPLOITED too (to be run on API 34). | pending | n/a | pending | pending | none (not a block) | L38 (to be written). |
| 3 | Open redirect `next=https://attacker.invalid/login` (`t3_open_redirect.sh`) | EXPLOITED | EXPLOITED | **blocked**, `PARAM_URL_NOT_ALLOWED` on `param:next`. The host is not allowed. | pending | n/a | pending | pending | `UriPolicyValidatorTest.blocksOpenRedirectToUnlistedHost` (exists) | |
| 4 | Link hijacking (`t4_link_hijack.sh`) | EXPLOITED | EXPLOITED | **not prevented**, on both APIs. The OS sends the link to `:attacker`, so `LinkActivity` (and ShezGuard) never run and no audit line is expected. | pending | pending | pending | pending | none | Build-time check in step 13; L3, L32. |
| 5 | Serializable of an unknown class (`t5_malformed_bundle.sh`) | EXPLOITED (crash) | EXPLOITED (crash) | **blocked, no crash**, `EXTRAS_UNPARCEL_FAILED`. API 34: on `extra:profile` (one lazy value fails). API 29: on the whole extras (`keySet()` unparcels everything). The exception is caught inside ShezGuard. | pending | pending | pending | pending | **To add:** `blocksSerializableOfUnknownClassWithoutCrashing`. No Serializable test exists yet. | |
| 5 (5b) | Gadget `LegacyProfile.readObject` (`t5_malformed_bundle.sh gadget`) | EXPLOITED | EXPLOITED | **not prevented**, on both APIs. ShezGuard reads every extra (to find nested intents), so `readObject` runs inside ShezGuard before any decision. The decision is then **Sanitize** with `EXTRA_NOT_ALLOWED` on `extra:profile`, and the app shows `profile=none`. | pending | pending | pending | pending | **To add:** `gadgetReadObjectRunsDuringExtrasInspection`, which documents the limitation and does not prove a block. | L1, L27. Needs `appFilesDir` set in `DemoApp` (decision 2) and R8 keep rules for `LegacyProfile` in the minified build. |
| 6 | Manual check vs encoding (`t6_encoding_manual_check.sh`), 3 payloads | EXPLOITED | EXPLOITED | Raw `../secret.txt`: ShezGuard **allows** it, then the manual check rejects it. `%2e%2e%2fsecret.txt`: **not prevented** (Allow, decodes once to `../secret.txt`; needless-escape detection applies only to the path). `%252e%252e%252fsecret.txt`: **blocked**, `URI_DOUBLE_ENCODING` on `uri.query`. The script as a whole is predicted **EXPLOITED** (the second payload). | pending | n/a | pending | pending | `UriCanonicalizerTest.blocksDoubleEncodingInQueryValue` (exists; covers only the third payload) | |

Vulnerable re-runs after decision 2: `LegacyProfile.appFilesDir` moves to `DemoApp.onCreate`, so `t5` and
`t5 gadget` are run again on the vulnerable flavor. The prediction is that nothing changes on API 34 or
API 29 (crash; `CANARY-GADGET-24`). Results: pending.

### R8 (`protectedMinified`, API 34)

Every row above is predicted to give the same RESULT line as the unminified protected build, and every
`ShezGuard` audit line is predicted to name its entry point (`ep=<name>`), with **no**
`ENTRY_POINT_NOT_ANNOTATED` or `<unannotated>`. The prediction relies on two things:
- the library's consumer rules (L36), which keep `@GuardedEntryPoint`;
- the app's Serializable keep rules for `LegacyProfile`. Without them, 5b would turn into the
  unknown-class case.

Results: pending.

### Benign controls

Script result values: `WORKS`, `BROKEN`, `INCONCLUSIVE`. Every benign script is run on both flavors on
API 34 and API 29, and on `protectedMinified` on API 34.

| Script | Legitimate request | Prediction, vulnerable | Prediction, protected (and minified) | Results |
|---|---|---|---|---|
| `b1_forward.sh` | Helper app (`benign_forward`). `next` is VIEW `https://shezguard.example/search?q=mug`, targeting `SearchActivity`. | WORKS | WORKS. **Sanitize** (`NESTED_INTENT_SANITIZED`, always for an allowed nested intent): the app forwards the sanitizer's output. `SearchActivity` is then Allowed by its own guard and returns `results=[Blue mug]`. | pending |
| `b2a_search.sh` | `/search?q=blue%20mug` | WORKS | WORKS, Allow | pending |
| `b2b_preview.sh` | `/preview?url=https%3A%2F%2Fshezguard.example%2Fhelp` | WORKS | WORKS, Allow. The page itself fails to load in both flavors, because the app has no INTERNET permission. | pending |
| `b2c_file.sh` | `/file?name=readme.txt` | WORKS | WORKS, Allow | pending |
| `b2d_note.sh` | `note="Buy milk"`, `copies=2` | WORKS | WORKS, Allow | pending |
| `b3_redirect.sh` | `/redirect?next=https%3A%2F%2Fshezguard.example%2Fhelp` | WORKS | WORKS, Allow | pending |
| `b4_login.sh` | `https://shezguard.example/login?token=abc123` and `shezdemo://login?token=abc123`, explicit package | WORKS | WORKS, Allow for both. Least certain: the custom-scheme URI has an empty path, and this is the first device run of a non-http scheme. | pending |
| `b5_profile.sh` | Helper app (`benign_profile`). `profile` is `LegacyProfile("alice")`. | WORKS | **BROKEN, by design**: Sanitize with `EXTRA_NOT_ALLOWED`, and the app shows `profile=none`. A Serializable extra cannot be allow-listed (L6), and `readObject` still runs (5b). | pending |
| `b6_manual.sh` | `/manual?name=readme.txt` | WORKS | WORKS, Allow | pending |

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

Results: pending.

## Not covered in v1

| Attack surface | Threat (SPEC section 2) | Why not covered | Limitation |
|---|---|---|---|
| An Intent held inside a custom `Parcelable` or `Serializable` extra | 1 (intent redirection) | Object fields are opaque to ShezGuard; only framework containers are searched | `docs/LIMITATIONS.md` L26 |
| `ClipData` of the incoming intent (including `ClipData.Item` intents and URIs) | 1 | Only extras are inspected; ClipData is checked only on nested intents, by `IntentSanitizer` | L26 |
| The selector of the incoming intent (`Intent.getSelector()`) | 1 | Not inspected | L26 |
| URI-permission grant flags (`FLAG_GRANT_*_URI_PERMISSION`) on the incoming intent | 1 | Flags are not inspected; on nested intents they depend on the developer's `IntentSanitizer` | L26 |
