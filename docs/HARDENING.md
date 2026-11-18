# ShezGuard: step 15 hardening review

Adversarial review of `:shezguard-core` and the `:shezguard-lint` rule, 2026-11-18, with the author's review decisions
of the same day applied. **No library behaviour was changed.** Not committed.

## How to run, and what the evidence is

```
./gradlew :shezguard-core:hardeningTest     # Robolectric (JVM)
./gradlew :shezguard-lint:hardeningTest     # lint-tests (JVM)
scripts/device/run_shared_tests.sh <AVD> <label>   # emulator; includes HardeningDeviceTest
```

- **Every red `hardeningTest` failure is a finding.** A failing test asserts a protection ShezGuard claims. Tests named
  `observes...` record behaviour outside the stated scope, `holds...` are negative results, and `characterises...` /
  `measures...` record numbers. These all pass.
- Sources: `shezguard-core/src/hardeningTest/java/com/shezguard/core/hardening/`,
  `shezguard-lint/src/hardeningTest/java/com/shezguard/lint/hardening/`, and the device test
  `shezguard-core/src/androidTest/java/com/shezguard/core/device/HardeningDeviceTest.kt`.
- **Separate from the normal suite.** Neither `hardeningTest` task is part of `test` or `check`. In `:shezguard-core`, the
  hardening directory is compiled into the debug unit-test classes only when `hardeningTest` is on the command line,
  and every normal `Test` task also excludes the package. `./gradlew :shezguard-core:test` still runs 896 tests per
  variant with unchanged names (checked by diffing the test-result XML before and after).
- **The three device tests record results and pass either way.** `HardeningDeviceTest.recordsH1DeepListOverflowOnMainThread`,
  `recordsH2DoubleSlashPath` and `recordsH4LongReferrer` print lines tagged `[H1]`, `[H2]`, `[H4]`. The device results
  below come from those tagged lines in `tagged.txt`, not from pass/fail. `scripts/device/extract_tagged.py` was
  extended to keep `[H<n>]` tags.
- **Evidence folders.**
  - `docs/results/2026-11-18_Pixel_8_api34_phase5-hardening/` and
    `docs/results/2026-11-18_ShezGuard_API_24_api24_phase5-hardening/`: the full instrumented suite plus the three
    device tests, 89 tests per level, 0 failures, run with `scripts/device/run_shared_tests.sh`. Scrubbed by the
    script's gate.
  - `docs/results/2026-11-18_robolectric_jvm_phase5-hardening/`: copies of the JVM reports (`fuzz.txt`,
    `sink-fuzz.txt`, `resource.txt`, `caller-referrer.txt`), scrubbed and checked with `scripts/device/scrub.py`.
- **Wording.** "Confirmed (emulator, API N)" means an emulator image ran it: real ART and native `Parcel`, but no real
  binder IPC from another app in these three tests, and not a physical device. "JVM/Robolectric" means HotSpot 17
  with Robolectric SDK 34 (some tests also SDK 29).

## Ranking

| Rank | ID | Severity / class | Finding | Where shown |
|---|---|---|---|---|
| 1 | H2 | Medium, bypass | `Uri.getPath()` keeps `//` that ShezGuard collapses. The intent is allowed with a soft signal only, while the app's `getPath()` is a network-path reference (`//evil.example/...`). | confirmed (emulator, API 34, 24); JVM fuzz |
| 2 | H1 | Medium, bypass | A deeply nested `List` extra makes `evaluate` throw `StackOverflowError`. The guarded app crashes even if it never reads that extra. | confirmed (emulator, API 34, 24); JVM |
| 3 | H3 | Medium, bypass, sink-dependent | `..;` path segments pass `prefix("/product/")`; servlet-style normalisation resolves them as `..` | JVM; sink model only |
| 4 | H6 | Low, outside stated claims (L45) | A built policy can be changed after build | JVM |
| 5 | H8 | Low, outside stated claims (L46) | Parser-mismatch check is O(N²) when `maxUriLength` is raised | JVM, measurement |
| 6 | H5 | Low, **consistency issue** | Intent inside a framework Parcelable gives Sanitize instead of Block; the object is removed either way | JVM (SDK 29, 34) |
| 7 | H7 | **By design, possible extra warning** | Lint accepts `exempt = true` on a data-reading BROWSABLE activity | lint-tests |
| — | H4 | **Not reproduced on device** (emulator API 34, 24); JVM-only | Long referrer, `java.util.regex` recursion in `PACKAGE_NAME` | JVM characterisation |

**Why H2 ranks above H1.** H2 defeats a check ShezGuard explicitly claims (the parser-mismatch check, "on any difference
the intent is blocked") and leads to an integrity problem, an open redirect (threat 3). It is reachable from a web link,
because a browser can deliver `https://example.com//evil.example/...`, so the attacker needs no app on the device. It
passes with only a weight-5 soft signal. H1 is availability only (a crash). It needs an installed app that can send
extras, and it falls under ShezGuard's documented carve-out for `Error`s (quoted under H1), although the documentation
understated its effect.

---

## Findings

### H2 (rank 1, Medium). `getPath()` disagrees with the checked path; network-path reference on Allow
- **Claim it breaks.** `ParserMismatch` KDoc: "The app may later read the URI through `android.net.Uri`, so ShezGuard's
  canonical view and the platform's view must agree; on any difference the intent is blocked." `getPath` is one of the
  accessors it reads (SPEC 5.3), but only for the trailing slash.
- **Mechanism.** The canonicaliser collapses empty path segments (`URI_NON_CANONICAL`, SOFT, weight 5). `getPathSegments`
  skips them too, so the mismatch check agrees, but `Uri.getPath()` keeps them.
- **Reproducer.** `https://example.com//evil.example/landing` on an `anyPath()` entry point gives **Allow**
  `[URI_NON_CANONICAL]`. `Decision.data.path` is `/evil.example/landing`, `intent.data.path` is
  `//evil.example/landing`, and `URI("https://example.com/").resolve(intent.data.path)` gives
  `https://evil.example/landing`. With a prefix pattern the host is limited to the first allowed segment:
  `//product/x` resolves to host `product`.
- **Where shown.** Confirmed (emulator, API 34) and confirmed (emulator, API 24): the `[H2]` lines are identical on both.
  JVM: `ValidatedVsUsedHardeningTest.allowedIntentUriGetPathMustAgreeWithCheckedPath` (red), the first fuzz
  (1 244 of 10 863 Allows) and the sink fuzz below.
- **Mitigating.** SPEC 6 tells apps to read from the `Decision`, which has the collapsed path; the signal is recorded.

### H1 (rank 2, Medium). A deeply nested List extra crashes the guarded app through `evaluate`
- **Where the recursion is.** In the **framework**, not in ShezGuard: `Parcel.readValue → readArrayListInternal`
  (`readArrayList` on API 24) `→ readListInternal → readValue → ...`, one cycle per nesting level. ShezGuard triggers it
  **by reading every extra**: the first ShezGuard frame below the cycle is `AndroidExtras.valueAt`, the top-level
  `Bundle.get(key)`, on API 34 and the JVM. On API 24 it is `AndroidExtras.read`, the `keySet()` call that unparcels
  every value eagerly. ShezGuard's own depth-limited walk (`classify`, `MAX_NESTING_DEPTH` 4) never starts. Frames were
  taken from a leaf Parcelable whose `CREATOR` records the stack at the deepest point (`DepthProbe`).
- **Frames per nesting level:** 4.0 (emulator, API 34), 3.0 (emulator, API 24), 8.0 on the JVM (Robolectric
  instrumentation doubles each frame).
- **Overflow depth, on the main thread** (emulator image, **indicative**: frame sizes depend on the ART build, the
  compilation state and what else is on the stack):

  | Where | `evaluate` ok at | `StackOverflowError` at | Parcel at that depth | Accuracy |
  |---|---|---|---|---|
  | emulator, API 34 (Pixel_8 image) | 1 734 | 1 750 | 21 168 bytes | bisection, within ~1 % |
  | emulator, API 24 (ShezGuard_API_24 image) | 25 937 | 26 093 | 208 948 bytes | bisection, within ~1 % |
  | JVM, Robolectric SDK 34, 8 MB thread | 1 000 | 2 000 | — | coarse grid only (see note) |

  Both device payloads are far below the ~1 MB binder limit. The API 34 payload is 21 KB.
- **App-only reads at the overflow depth.** API 34: reading only `data`/`action` is fine, and so is reading another extra
  (the List is lazy on 33+). Calling `Bundle.get("deep")` directly also overflows, which confirms the cause is the
  framework read. **API 24, small margin:** at depth 26 093, `Bundle.get` alone and an app reading another extra did
  *not* overflow. ShezGuard's own frames beneath `keySet()` take just enough stack to cross the limit first. By source
  reading, an app that reads any extra on API 24–32 would overflow only slightly deeper, but the bisection step
  (~156 levels) cannot show where.
- **JVM note.** Bisecting with repeated `StackOverflowError`s deadlocked Gradle's test worker twice. Under Robolectric
  SDK 29, the first overflow also poisoned class initialisation (`NoClassDefFoundError`). The JVM depth is therefore a
  coarse grid that stops at the first overflow, and the red JVM test runs on SDK 34 only.
- **Claim it breaks.** SPEC 2, threat 5 (in scope): "Malformed Bundles that crash the app". SPEC 5 step 4: "catch,
  record `EXTRAS_UNPARCEL_FAILED`, never crash."
- **The documented carve-out for `Error`s**, verbatim:
  - `ShezGuard.evaluate` KDoc: "This function does not throw for any intent: a `RuntimeException` during evaluation
    becomes a Block with `EVALUATION_FAILED`. `Error`s are not caught."
  - SPEC 5.3: "Any `RuntimeException` during evaluation gives Block with a single `EVALUATION_FAILED` ... `Error`s are
    not caught."
  - SPEC 5.4: "Each read catches `RuntimeException` only".
  - `AndroidExtras` KDoc: "`Error`s are not caught."

  **Does it need changing? Yes.** The sentences describe the code correctly, but "does not throw for any intent" is
  false for this intent: a 21 KB attacker parcel is enough. At minimum the KDoc and SPEC should state that an
  attacker-chosen extra can make the extras read throw `StackOverflowError`. If step 16 catches it (plan below), the
  carve-out itself changes. L28's wording "as it would without ShezGuard" has already been corrected.
- **Tests.** JVM: `ResourceExhaustionHardeningTest.evaluateMustNotCrashOnDeeplyNestedListExtraTheAppNeverReads` (red);
  `measuresH1OverflowDepthAndRecursingFrames` (numbers). Device: `HardeningDeviceTest.recordsH1DeepListOverflowOnMainThread`.

### H3 (rank 3, Medium, sink-dependent). `..;` segments escape a path prefix in servlet-style sinks
- **Claim it breaks.** `PathPattern.Prefix` KDoc: "matching stops at a segment boundary: `/product/` matches `/product/42`
  but never `/product-admin`". SPEC 6 rejects `..` segments raw and encoded (threat 2).
- **Reproducer.** These are allowed under `prefix("/product/")`: `/product/..;/admin`, `/product/..;jsessionid=1/admin`,
  `/product/%2e%2e;/admin`, `/product/..%3B/admin`, `/product/.;/..;/admin`. Tomcat/Spring-style normalisation strips
  `;…` and then resolves `..`.
- **Arguable.** Per RFC 3986, and for `android.net.Uri` and `java.io.File`, `..;` is not a dot-segment. The escape exists
  only in sinks with path-parameter semantics. **Not run against a real server.**
- **Test.** `CanonicaliserHardeningTest.blocksMatrixParamDotDotSegmentEscapingPathPrefix` (red); sink fuzz below.

### H6 (rank 4, Low, outside stated claims: L45). Policies can change after they are built
- `IntentPolicy.entryPoints` is a mutable `LinkedHashMap`. The public `EntryPointPolicy` and `ExtrasRule` constructors keep
  the caller's collections, so later changes bypass their `init` checks and the DSL. Needs code inside the app, or a
  developer who mutates a collection after passing it in.
- **Test.** `PolicyHardeningTest.builtPolicyCannotBeChangedAfterBuild` (red).

### H8 (rank 5, Low, outside stated claims: L46). Quadratic parser-mismatch cost with a raised `maxUriLength`
- JVM only, single runs, `maxUriLength = 1_000_000`: 2 000 distinct parameters 19 ms, 4 000 75 ms, 8 000 299 ms,
  16 000 1 100 ms (×3.7 per doubling). About 55 000 fit in a 1 MB transaction, extrapolated to ~13 s. At the default
  limit the worst case is ~1 ms.
- **Test.** `ResourceExhaustionHardeningTest.measuresQuadraticParserMismatchWithARaisedUriLimit` (measurement, passes).

### H5 (rank 6, Low, consistency issue). Intent inside a framework Parcelable: Sanitize, not Block
- **Inconsistent with.** `Nested.Deny` KDoc: "Any nested Intent blocks (`NESTED_INTENT_DENIED`)."
- **Reproducer.** Extra `clip` = `ClipData.newIntent("x", evil)` (after a round trip, SDK 29 and 34), or a `Notification`
  whose `contentIntent` is a `PendingIntent` (in-process). Both give **Sanitize** `[EXTRA_NOT_ALLOWED]`.
- **Why a consistency issue, not a bypass.** The object is opaque (`ExtraValue.Other`), never an allowed type, and is
  **removed either way**. It never reaches the app through ShezGuard. Only the outcome label (Sanitize instead of Block)
  and the missing `NESTED_INTENT_DENIED` differ from the KDoc.
- **Test.** `NestedIntentHardeningTest.blocksIntentHiddenInsideFrameworkParcelableExtra` (red).

### H7 (rank 7, by design, possible extra warning). Lint accepts `exempt = true` on a data-reading BROWSABLE activity
- `exempt = true` is the documented explicit opt-out, like `@SuppressLint`. The rule's own message limits it to
  activities that read no intent data, but does not check that. A possible extra Warning is discussed in the plan below.
- **Test.** `LintHardeningTest.flagsExemptBrowsableActivityThatReadsIntentData` (red; it asserts the possible warning).

### H4 (not reproduced on device; JVM-only). Long referrer and `java.util.regex` recursion
- On the JVM, `PACKAGE_NAME.matches` on a 100 015-char caller-chosen `EXTRA_REFERRER_NAME` (200 KB parcel) throws
  `StackOverflowError` from HotSpot's `java.util.regex`, which recurses per group repetition. `guarded {}` catches
  `RuntimeException` only, so the error leaves `evaluate`. Only `allowedPackages` entry points read the referrer.
- **Not reproduced (emulator, API 34)** and **not reproduced (emulator, API 24)**: Android's ICU-backed regex returned
  normally for referrers up to 240 015 chars; `evaluate` returned a decision.
- **No library fix proposed.** Optional, for JVM users of the pure-Kotlin parts only: a length pre-check before the
  regex (a package name is short).
- **Tests.** `CallerReferrerHardeningTest.characterisesH4LongReferrerOnTheJvm` (passes, records);
  `HardeningDeviceTest.recordsH4LongReferrer`.

---

## Results per review area

### Area 1: validated vs used
Finding H2. Re-observed and outside scope (L26): the selector of an allowed intent is never checked; a ClipData URI
with grant flags survives Allow; the sanitized copy keeps selector, ClipData and grant flags. `Decision.Allow.intent` is
the caller's mutable object (in-process, outside the threat model). **Held:** after a Parcel round trip (SDK 29, 34) the
app reads the same allowed extras ShezGuard checked; a crafted `OpaqueUri` that prints as `https://…` is blocked.

### Area 2: canonicaliser
Finding H3. **Held:** Turkish default locale (dotless/dotted i, Kelvin sign); digest hex under non-Latin digit locales;
Cyrillic, fullwidth and punycode hosts; trailing dot; fullwidth and Arabic-Indic digits; RLO/RLM; fullwidth dots;
NFD vs NFC (no normalisation, so no match); `javascript:`, `intent:`, `content:`, `file:`, `data:`, `https:host`,
userinfo, `\@`, odd ports, IPv6; URL-typed parameter tricks; raw, encoded, double-encoded and overlong `..`; encoded
separators; `%00`; tab inside `..`; long percent runs.

### Area 3: nested intents
Result: **no bypass; one consistency issue (H5).** **Held** (SDK 29 and 34, after a round trip, all
`NESTED_INTENT_DENIED`): `Parcelable[]`; `Intent[]` under an allowed `STRING_ARRAY` key; `ArrayList<Bundle{Intent}>`;
`SparseArray`; `HashMap` key and value; `LabeledIntent`; 3 containers; exactly 4 containers (Bundle chain, and mixed
Bundle > List > Bundle > SparseArray); an Intent wrapped in a Bundle under the `AllowSanitized` key; a `null` key. Five
containers give `EXTRAS_TOO_DEEP`, unread. In-process cycles (self-containing Bundle and List) terminate. A nested
intent's selector is dropped by `IntentSanitizer`. Tests: `NestedIntentHardeningTest.holds*`. Out of scope and already
documented (L26): the incoming intent's own selector and ClipData.

### Area 4: policy and DSL
Finding H6 (L45). **Held:** 8 threads × 8 000 evaluations of a shared policy match single-threaded results; the bare
entry point and empty allow-lists fail closed; the DSL rejects 11 empty or unsafe forms; confusable entry point names
never reach another policy.

### Area 5: resource exhaustion (JVM numbers, indicative)
Findings H1 and H8; H4 is JVM-only. **Held at default limits:** 2 046-char URI with 305 distinct parameters 1.0 ms /
0.5 MB; 438 911-char URI (over the limit, still parsed in full) 8.7 ms / 24.4 MB, linear; one unknown `IntArray(240000)`
9.7 ms / 34.6 MB; 50 000 int extras 54 ms / 37.7 MB (L28: read before removal). No ReDoS by time: the regexes on attacker
input are `UUID` (anchored, fixed length) and `PACKAGE_NAME` (13 ms on 1 MB).

### Area 6: audit sink, logcat, `toString()` and exception messages
Result: **held, no finding.** The canary `zqxcanary` was placed in action, type, category, package, component,
selector, ClipData, a `CREATOR` exception message, an allowed extra value, undeclared parameter names and values,
dropped parameters, nested intent component/data/extras, an unknown key holding an intent, host and fragment: 15 inputs
× 3 entry points = 45 evaluations, 45 events, 45 logcat lines. The canary appeared in no `Decision`, `Violation`,
`Field`, `RiskScore`, `GuardedUri` or `CheckedIntent` `toString()`, no `declaredName`, no `AuditEvent` field or
`toString()`, no logcat line, and no message of any Throwable escaping `evaluate`. Test:
`AuditLeakHardeningTest.noCanaryInAnyOutputToStringLogOrExceptionMessage`. The `StackOverflowError`s of H1 and H4 carry
no message.

### Area 7: Lint rule bypasses beyond H7
Result: **no new bypass beyond H7; two known blind spots re-observed.**
- Known (L4): an annotated activity that guards `onCreate` but consumes the raw intent in `onNewIntent` is accepted.
- Known (receivers out of v1, L41): an exported receiver registered at run time is invisible.
- **Held:** `android:exported="${placeholder}"`, `"@bool/x"` and `"TRUE"` are treated as exported (conservative). An alias
  whose target is unannotated is flagged even when the alias name matches an annotated class.
- Tests: `LintHardeningTest.observes*` and `holds*`.

### Area 8: differential fuzz

**Run 1 (accessor agreement).** JVM, seed `0x5EED0015`, 40 000 inputs. Generator:
`DifferentialFuzzHardeningTest.generate` (grammar over schemes, hosts, ports, path tokens, query pieces and fragments) on
even n, `mutate(generate)` (insert, delete, duplicate, percent-encode, percent-decode) on odd n. 10 863 Allows, 0
`EVALUATION_FAILED`. Categories:

| Category | Cases | Status |
|---|---|---|
| `getPath()` keeps `//` | 1 244 | H2 |
| `getQueryParameters` / `getQueryParameter` and `+` | 1 213 + 1 121 | known, L11 |
| `getHost()` keeps the sender's case | 5 519 | by design |

No other category.

**Run 2 (sink-model oracles).**
- **The sink models are not real servers.** "Resolution" is `java.net.URI.resolve` of the path against
  `https://<checked host>/`. "Servlet" is a servlet-style normaliser written for this test: split `getEncodedPath()` on
  `/`, strip `;params` from each segment, percent-decode each segment, drop empty and `.` segments, apply `..`. No
  Tomcat, Spring or WebView was run.
- **Counts measure coverage, not prevalence.** The generator deliberately over-produces `//`, `;`, `..;` and `%2F`, so
  the counts show which classes exist; they say nothing about real traffic.
- Generator: `SinkOracleFuzzHardeningTest.generate` (the run 1 tokens plus `;`, `;x=1`, `..;`, `.;`, `;jsessionid=…`,
  `%3B`, `%2e%2e;`, `%2F`, `%2f`, `%252F`, `/`, `//`) and `mutate` (insert from an alphabet, delete, insert `//`, `;`,
  `..;`, `%2F`, `/../`, `;x=1/`). 400 000 inputs per seed (10× run 1). Each input is evaluated against an `anyPath()` and
  a `prefix("/product/")` entry point. Under 3 s per seed.

| Class | seed `0x514B0001` | seed `0x514B0002` |
|---|---|---|
| Allows (any / prefix) | 160 251 / 89 634 | 160 108 / 89 041 |
| H2-like, `getPath()` resolves to another host, anyPath | 1 718 | 1 696 |
| H2-like, prefix entry point (`//product/…` resolves to host `product`) | 292 | 214 |
| H2-related, `//` with no authority that `java.net.URI` cannot resolve | 13 687 | 13 587 |
| H3-like, servlet normalisation escapes `/product/` | 10 058 | 9 782 |
| H3 boundary, normalises to `/product` (no trailing slash) | 2 995 | 3 078 |
| **New**: the checked path itself resolves to another host, or lies outside the prefix | 0 | 0 |

## Not done
- Duplicate keys in a hand-written Bundle parcel (the platform's `ArrayMap.validate` should reject them; not crafted).
- Activities in dynamic feature modules (Lint sees only the base merged manifest; not tested).
- A Chromium/WHATWG parser comparison for URL-typed parameters and WebView loads (reasoned, not run).
- H3 against a real server (only the servlet-style model).
- H1 through real binder IPC from a second app (device runs used an in-process Parcel round trip on the main thread),
  and on API 29/33/36.

---

## Proposed step 16 plan (not implemented)

| ID | Fix / document | Proposed change | Hardening test that would move into `test` | Existing tests (of the 896) affected | Public API / earlier claims |
|---|---|---|---|---|---|
| H2 | **Both** | Make a path that starts with an empty segment (`//…`, a network-path reference for `getPath()`) **HARD**, as a new code (e.g. `URI_PATH_NETWORK_REFERENCE`) or as `URI_PARSER_MISMATCH` on `PATH`. Interior `//` stays soft but is documented as differing in `getPath()`. Stricter option: compare `getPath()` exactly in `ParserMismatch`, which also blocks interior `//`. | `allowedIntentUriGetPathMustAgreeWithCheckedPath` (only its leading-`//` cases with the minimal fix), plus the two device `[H2]` lines as assertions | Minimal fix: `AuditWiringTest` case "scored" (`https://example.com//search`) is still Block, but by a hard code instead of the score; it needs another soft vehicle (e.g. a needless escape) to keep testing the score path. `UriCanonicalizerDifferentialTest.trickyParseable` (`$base//a//b`): re-check, because it is an input-contract case. Stricter option, additionally: `ShezGuardEvaluateTest.allowsDuplicateSlashesButListsNonCanonicalSignal` and the `ScoringEvaluateTest` cases built on `/a//b` (4 tests) | **Behaviour change against SPEC 6** ("Normalise path separators and duplicate slashes ... record a low-severity violation"). A new `ViolationCode` entry is a public API addition (exhaustive `when` in apps). |
| H1 | **Both** | Catch `StackOverflowError` (only that `Error`) around ShezGuard's own extras reads in `AndroidExtras` (`keySet`, `get`) and report `EXTRAS_UNPARCEL_FAILED` (HARD, Block). Keep all other `Error`s propagating. Document that this stops ShezGuard from introducing the crash, not an app that reads the extra itself. | `evaluateMustNotCrashOnDeeplyNestedListExtraTheAppNeverReads`, preferably moved to `src/sharedTest` so the emulators run it too. Caveat: repeated JVM overflows deadlocked Gradle's worker, so keep it to one overflow per test JVM. | `ParserMismatchTest.errorsAreNotCaught` asserts that an `Error` from the **URI input** propagates through `Evaluator.evaluate`. A narrow catch inside `AndroidExtras` leaves it unchanged; a broad catch in `Evaluator` would break it. | **Changes the documented carve-out** (`ShezGuard.evaluate` KDoc, SPEC 5.3/5.4, `AndroidExtras` KDoc). No public API change. |
| H3 | **Both** (fix optional) | Option: reject a segment whose part before the first `;` is `.` or `..` (raw or decoded) as `URI_PATH_TRAVERSAL` / `URI_PATH_DOT_SEGMENT`. Document the sink dependence next to L37 either way. | `blocksMatrixParamDotDotSegmentEscapingPathPrefix` | None found: no existing test uses `..;` or `.;` (searched for `..;`, `;x=`, `a;b`, `%3B`). | Behaviour change (stricter): paths with `..;` would be blocked. No API change. |
| H6 | **Fix** (and close L45) | Defensive, unmodifiable copies in the constructors of `IntentPolicy`, `EntryPointPolicy`, `ExtrasRule`, `Nested.AllowSanitized`, `Caller.AllowedPackages`, `ParamType.OneOf`/`Url`, `ScoreWeights`; validate after copying. | `builtPolicyCannotBeChangedAfterBuild` | None expected (no test relies on mutating a policy); re-run `PolicyModelTest`. | No signature change. Behaviour: casting to mutable then throws. |
| H8 | **Both** (and close L46) | Put an upper bound on `maxUriLength` (e.g. 16 384), and/or make the check linear by reading `getQueryParameter` only once per name with an index. Document the bound. | none (measurement); add a bound test to `PolicyModelTest` / `PolicyDslTest` | `PolicyModelTest` and `PolicyDslTest` limits tests use 1024, 40 and 0: unaffected by an upper bound. | `Limits(maxUriLength > bound)` would throw: a **public behaviour change** for apps that raised the limit. |
| H5 | **Document** (L26) | State that framework Parcelables that carry intents (`ClipData`, `Notification`, …) are opaque and removed (Sanitize), not reported as nested intents. Optionally special-case `ClipData` items. | none (or the ClipData half, if special-cased) | none | Only if fixed: Block instead of Sanitize for such extras. |
| H7 | **Document**, optional extra warning | Optional new Lint issue `ShezGuardExemptReachableEntryPoint` (Warning) for an `exempt` activity that is BROWSABLE or reads `getIntent()`. | `flagsExemptBrowsableActivityThatReadsIntentData` (into `:shezguard-lint` test, expecting one warning) | none (lint tests are not among the 896) | New Lint issue ID (not runtime API). |
| H4 | **Document** only | Keep as a JVM-only characterisation. Optional length pre-check for JVM users. | none | none | none |
