# Changelog

All notable changes to ShezGuard. ShezGuard is a research prototype: pre-1.0, not published to any remote repository
(install from `mavenLocal`, see `README.md`). Versions follow Semantic Versioning in spirit, but before 1.0 any release
may change the public API.

## 0.1.0 (2026-11-18): first packaged version

First version published as Maven artifacts (`io.github.shehroz-ameer:shezguard-core:0.1.0` AAR with the Lint rule and
consumer R8 rules inside, and `io.github.shehroz-ameer:shezguard-lint:0.1.0`), to `mavenLocal` only. Licensed under
Apache-2.0. It contains everything built in steps 1–14 (`docs/SPEC.md`) plus the fixes from the step 15 hardening review
(`docs/HARDENING.md`), listed below.

### Behaviour changes (step 16)

- **H8: links with more than 64 query parameters are now blocked by default** (`PARAM_TOO_MANY`, HARD). New
  `Limits.maxParameters` (default 64, at most 256, checked when the policy is built), counted on the raw query before
  any `android.net.Uri` accessor runs. Reason: `Uri.getQueryParameter` costs about the cube of the number of value-less
  parameters (5.2 s per call for 2 745 of them on an API 34 emulator). 64 and 256 are chosen limits, not derived.
- **H8: `Limits.maxUriLength` may not exceed 8192.** A larger value throws (`Limits(...)`) or is reported as a
  `PolicyDefinitionException` (DSL) when the policy is built.
- **H2: duplicate slashes in the path are now blocked** (`URI_PARSER_MISMATCH` on `uri.path`, HARD). The parser-mismatch
  check compares `Uri.getPath()` exactly; before, `https://example.com//evil.example/x` was allowed with only the soft
  `URI_NON_CANONICAL`, while `getPath()` returned a network-path reference (open redirect).
- **H3: `..;` and `.;` path segments are rejected** as dot segments (`URI_PATH_TRAVERSAL` / `URI_PATH_DOT_SEGMENT`,
  HARD), including encoded forms such as `%2e%2e;` and `..%3B`. Other `;` in paths stay literal (L47).
- **H1: `StackOverflowError` during ShezGuard's own extras reads is now caught** and fails closed
  (`EXTRAS_UNPARCEL_FAILED`, or `NESTED_INTENT_DENIED` inside a nested intent). Before, a deeply nested List extra
  (about 1 750 levels, a 21 KB parcel, on API 34) crashed the app even if it never read that extra. No other `Error` is
  caught; `OutOfMemoryError` still propagates.
- **H6: policy objects keep unmodifiable copies of their collections.** `IntentPolicy.entryPoints` and the collections
  of `EntryPointPolicy`, `Nested.AllowSanitized` and `ScoreWeights` can no longer be changed after construction, through
  a cast or through the caller's own collection; DSL-built data classes get unmodifiable collections. Residual: the data
  classes `ExtrasRule`, `ParamType.OneOf`, `ParamType.Url` and `Caller.AllowedPackages` still keep a caller's collection
  when constructed directly (L45).

### Public API additions

- `ViolationCode.PARAM_TOO_MANY` (HARD, MEDIUM).
- `Limits.maxParameters` (a third constructor parameter of the data class `Limits`, so `copy`/`component3` change too) and
  `Limits.DEFAULT_MAX_PARAMETERS` (64).
- DSL: a `maxParameters` argument on `limits(...)` in `entryPoint { }`.

### Documentation-only (no behaviour change)

- H5: an Intent inside a framework Parcelable (`ClipData`, `Notification`) is removed as `EXTRA_NOT_ALLOWED`, not reported
  as a nested intent (L26; `Nested.Deny` KDoc).
- H7: `@GuardedEntryPoint(exempt = true)` is accepted by the Lint rule even on a BROWSABLE activity that reads intent
  data; a warning is future work (L41).
- H4: a long caller-chosen referrer overflowed `java.util.regex` on the JVM only; not reproduced on emulators (API 34,
  24).
- KDoc corrections from the claims audit (`docs/CLAIMS_AUDIT.md`): "the intent is never modified" now says "no public
  state" (L21); the `Limits` KDoc gives measured costs.

### Tests

- New in the normal suite: `PathAccessorAgreementTest` (2, shared with the emulators), `ShezGuardEvaluateTest.blocksMatrixParamDotDotSegmentEscapingPathPrefix`,
  `UriCanonicalizerTest.blocksMatrixParamDotDotSegment`, `blocksMatrixParamSingleDotSegment`,
  `keepsSemicolonOutsideDotSegmentsLiteral`, `blocksQueryParameterFlood`, `PolicyImmutabilityTest` (2),
  `ParameterFloodTest` (2). Device-only: `DeepNesting{Evaluate,NestedIntent,OnNewIntent}DeviceTest`. JVM suite: 896 → 907
  tests per variant.
- **Renamed:** `ShezGuardEvaluateTest.allowsDuplicateSlashesButListsNonCanonicalSignal` →
  `blocksDuplicateSlashesAsParserMismatchAndKeepsNonCanonicalSignal` (now asserts Block).
- **Changed input, same assertions:** four `ScoringEvaluateTest` tests use `/a/%62` instead of `/a//b` as their soft
  `URI_NON_CANONICAL` signal (`//` is HARD now).
- **Extended:** `PolicyModelTest.limitsRejectNonPositiveValues` and `PolicyDslTest.rejectsOutOfRangeNumbers` (bounds for
  `maxUriLength` and `maxParameters`); `ViolationModelTest` code list (`PARAM_TOO_MANY`).
- Hardening suites (`hardeningTest`, not part of `check`) and mutation scripts `scripts/mutation/step16_*`.

### Build and tooling

- `maven-publish` (Gradle built-in) on `:shezguard-core` (release variant with sources jar) and `:shezguard-lint`.
- Every `Test` task has a 20-minute timeout. `hardeningTest` forks one JVM per class. Standing rule: tests that
  overflow the stack never run under Robolectric.
- Benchmark: `h8_*` scenarios, a per-call scenario filter, and `BENCH_SCENARIOS` / `BENCH_WARMUP` / `BENCH_SAMPLES` in
  `scripts/bench/run_bench.sh`.
