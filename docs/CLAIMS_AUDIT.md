# Claims audit (step 16 part 2)

Every protection or behaviour claim in `README.md` and in the KDoc of the public API, with its evidence. Evidence
labels follow `docs/PAPER_NOTES.md`: **confirmed (emulator, API N)**, **Robolectric-only**, **JVM** (pure Kotlin, no
Android types), **lint-tests**, **source-read only (AOSP, not run)**, **by construction** (enforced by the compiler or the
type), **design statement** (says what the code does or does not do; checked by reading the code, not by a test).
Test names are classes in `shezguard-core/src/test`, `src/sharedTest` (also run on the emulators), `src/androidTest`
(emulator only) or `shezguard-lint/src/test`. "Fixed" means the claim was changed in this step because it lacked
evidence or was wrong.

Audit date: 2026-11-18. Scope: `README.md`; public KDoc of `ShezGuard`, `Decision`, `GuardedUri`, `Violation`/`Field`,
`ActivityGuard`/`CheckedIntent`, `GuardedEntryPoint`, `AuditSink`/`AuditEvent`/`LogcatAuditSink`, the policy model and DSL
(`intentPolicy`, `EntryPointPolicy`, `HostPattern`, `PathPattern`, `ParamType`, `CharClass`, `ExtrasRule`, `Nested`,
`Caller`, `Limits`, `Threshold`, `ScoreWeights`) and `NestedIntentSanitizer`.

## Changed in this audit (claims without evidence, or wrong)

| Where | Old claim | Problem | Now |
|---|---|---|---|
| README, Activity helper | "Hilt, for example, injects them during `super.onCreate`, too late" | Hilt's injection point was never checked (L34 lists it as unread) | Softened: fields a DI framework injects during `super.onCreate`; which frameworks do so was not checked |
| README, Activity helper | Navigation / Compose / `addOnNewIntentListener` must run after the guard (stated as fact about where they read the intent) | L35: not verified | Kept as advice, marked **not verified** (L35) |
| README, Lint | "`assembleRelease` runs `lintVital`, Fatal only, so ShezGuard's Errors do not stop a release build" | never run in this project | Marked as AGP's documented behaviour, not run here |
| `ShezGuard.evaluate` KDoc | "[intent] is never modified" | L21: on API 33+ the copy constructor clears a private flag of the caller's extras; tests check public state only | "No public state of [intent] is modified", with the L21 note |
| `Limits.maxUriLength` KDoc, SPEC 4.2, L46 | the 8192 bound "keeps the worst case to a few milliseconds" (7.1 ms) | **wrong**: measured with `pN=1` parameters; value-less parameters cost ~100× more (`docs/HARDENING.md` H8) | Replaced with the measured worst case (724 ms JVM, 5.2 s per call on emulator API 34), then mitigated by the parameter cap: 483–494 µs per call after (L46) |

## README.md

| Claim | Evidence |
|---|---|
| Returns Allow / Sanitize / Block with every reason as a stable code; all violations collected | `ShezGuardEvaluateTest.collectsAllViolationsNotJustTheFirst`, `collectsAllCanonicalisationFindings`; `DecisionTest.blockRequiresAtLeastOneViolation` (Robolectric-only) |
| Unknown entry point name is blocked (`ENTRY_POINT_UNKNOWN`) | `ShezGuardEvaluateTest.blocksUnknownEntryPointByDefault` (Robolectric-only) |
| `intentPolicy {}` throws one `PolicyDefinitionException` listing every problem | `PolicyDslTest.collectsAllProblemsAcrossAllEntryPoints`, `exceptionIsAnIllegalArgumentExceptionListingEveryProblem` (JVM) |
| Data rule defaults to `Forbidden`; `allowSchemes` switches to `Required` | `PolicyDslTest.defaultsAreFailClosed`, `allowSchemesSwitchesDataToRequired` (JVM) |
| Exact hosts; subdomains only via `subdomainsOf` | `UriPolicyValidatorTest.blocksSubdomainWithoutExplicitOptIn`, `subdomainsOfMatchesOnlyStrictSubdomainsAtLabelBoundary` (JVM) |
| Prefix pattern stops at a segment boundary | `UriPolicyValidatorTest.prefixPatternStopsAtSegmentBoundary` (JVM); `..;` segments: `ShezGuardEvaluateTest.blocksMatrixParamDotDotSegmentEscapingPathPrefix` (H3, Robolectric-only) |
| Unknown params `Block`/`Drop`/`Ignore`; repeated params blocked | `ShezGuardEvaluateTest.blocksUndeclaredParamUnderDefaultUnknownBlock`, `blocksParameterPollution`; `SanitizeDropTest.dropsUnknownTrackingParamsAndKeepsTheRestByteForByte` (Robolectric-only) |
| Extras: allowed keys with type and size; everything else removed | `ExtrasEvaluateTest.allowsDeclaredExtrasOfTheRightType`, `blocksTypeConfusionUnderAllowedKey`, `blocksOversizedStringExtra`, `sanitizesUnknownExtraKeyByRemovingIt` (Robolectric-only) |
| Nested intents `Deny` (default) / `AllowSanitized` | `NestedIntentTest.denyIsTheDefault`, `blocks*`, `sanitizesNestedIntentThroughIntentSanitizer`: confirmed (emulator, API 24, 29, 33, 34, 36). Framework-Parcelable caveat: L26 (H5) |
| Caller: `allowedPackages` advisory unless the source is reliable; `requireReliableIdentity` blocks ordinary deep links | `CallerAndroidTest.*` (Robolectric-only); `CallerIdentityDeviceTest`: confirmed (emulator, API 24, 29, 33, 34, 36) (L30) |
| `requireVerifiedDomain` | `DomainVerificationDeviceTest`: confirmed (emulator, API 33, 34, 36); not applicable below 31 (L30) |
| URI length default 2048, at most 8192; parameter length default 256; at most 64 query parameters by default (max 256) | `PolicyModelTest.entryPointDefaultsAreMostRestrictive`, `limitsRejectNonPositiveValues`; `PolicyDslTest.rejectsOutOfRangeNumbers`; `UriCanonicalizerTest.blocksQueryParameterFlood`, `ParameterFloodTest` (JVM) |
| Outcome rule (HARD blocks; score ≥ threshold blocks; REMOVABLE sanitizes; else Allow) | `OutcomeRuleTest.*` (JVM); `WeightedScorerTest.noCombinationOfWeightsTurnsHardIntoAllowOrSanitize`, `scoreCanOnlyAddBlock` (JVM) |
| Sanitize only removes, never rewrites | `SanitizeDropTest.keepsComponentActionFlagsCategoriesTypePackageAndExtras`, `dropDoesNotRescueAHardViolation`; `NestedIntentTest.blocksNestedIntentWhoseComponentIntentSanitizerRewrites` (emulators API 24–36) |
| `GuardedUri` exposes only declared parameters; `Unknown.Ignore` parameters stay in the intent | `ShezGuardEvaluateTest.allowsCleanDeepLinkAndExposesCanonicalValues`, `ignoredUnknownParamIsSignalledButNotReadable` (Robolectric-only), L20 |
| Android's query accessors disagree about `+`; `GuardedUri` follows `getQueryParameter` | `UriCanonicalizerDifferentialTest` (tests 99, 111): confirmed (emulator, API 24, 29, 33, 34, 36); fuzz `DifferentialFuzzHardeningTest` (L11) |
| Caller section (forward-result caveat, no identity in `onNewIntent`, key rotation blocks) | `CallerIdentityDeviceTest` forward-result and new-intent cases: confirmed (emulator, API 24, 29, 33, 34, 36); key rotation: `CallerAndroidTest.rotatedOutSigningKeyIsNotAccepted` (Robolectric-only) |
| Activity helper outcome table (Allow / Sanitize / Block in `onCreate` and `onNewIntent`) | `ActivityGuardTest.*` (Robolectric-only; the device lifecycle check was cut, L34) |
| `@CheckResult` is a Lint warning only | design statement; built-in `CheckResult` check exercised in `GuardCallDetectorTest` (lint-tests) |
| Guard must run before `super.onCreate`; after process death `getIntent()` is the raw launch intent | `ActivityGuardTest.processDeathRedeliversTheRawIntentAndItIsSanitizedAgain` (Robolectric, simulated); N14 source-read only |
| ShezGuard cannot prevent the launch | design statement (L34) |
| A blocked `onNewIntent` is ignored, not finished | `ActivityGuardTest.newIntentBlockIsIgnoredAndTheSessionKeepsItsCheckedState` (Robolectric-only) |
| Every creation is evaluated; no cached decision | `ActivityGuardTest.recreationIsEvaluatedUnderTheCurrentPolicyNotACachedDecision` (Robolectric-only); mutants d1–d3 (`docs/MUTATION_CHECKS.md`) |
| Annotation not inherited; missing/empty/exempt is blocked; R8 keeps the annotation | `ActivityGuardTest.annotationIsNotInheritedBySubclasses`, `missingAnnotationIsDenied`, `exemptEmptyAndContradictoryAnnotationsAreDenied` (Robolectric-only); R8: one minified build, emulator API 34 (L36, step 12) |
| Serializable extras + R8: weak keep rules crashed natively | observed on emulator API 34, step 12 (L40, N15) |
| Lint issue table (IDs, severities, what each reports, confidence) | `CoverageDetectorTest`, `GuardCallDetectorTest`, `DeepLinkDetectorTest` (lint-tests); demo negative control (`docs/MUTATION_CHECKS.md`, step 13) |
| `lint.jar` is loaded in modules that depend on ShezGuard (project dependency) | demo app, step 13 (`app/README.md`); published AAR not tested (no publication) |
| `checkDependencies = true` makes missing policy names Errors (9 Errors in the vulnerable flavor) | demo run, step 13 (`app/README.md`, SPEC 9) |
| Older AGP silently skips the rule | design statement from Lint's registry API levels (L41); only AGP 8.10.1 tested |
| One redacted `AuditEvent` per evaluate call, after the decision; no raw values | `AuditWiringTest.everyOutcomePathEmitsExactlyOneMatchingEvent`, `evaluationFailedEmitsExactlyOneEvent`; `AuditCanaryTest` (Robolectric-only); `AuditLeakHardeningTest` (Robolectric-only) |
| Sink runs synchronously; may be called concurrently | design statement (L33); `LogcatAuditSinkTest.capHoldsUnderConcurrentCalls` (Robolectric-only) |
| Sink exceptions swallowed; `Error`s propagate | `AuditWiringTest.throwingSinkDoesNotChangeTheDecision`, `errorsFromTheSinkPropagate` (Robolectric-only) |
| `LogcatAuditSink` logs Block by default, 30 lines per minute | `LogcatAuditSinkTest.onlyBlocksAreLoggedByDefault`, `floodIsCappedPerMinuteWithOneSuppressedLine` (Robolectric-only) |
| Violations never expose an undeclared name; `toString()` safe to log | `RawNameExposureTest.noPublicApiReturnsAnUndeclaredName`, `fieldsKeepValueEqualityAndRedactedToString`; `AuditLeakHardeningTest` (Robolectric-only) |
| "What ShezGuard does not do" list | each item points to its L-entry and matrix row (t2a, t2c, t4, t6, 5b); these are limitation statements |
| Tested API levels 24, 29, 33, 34, 36 only | `docs/results/2026-11-17_*` and `2026-11-18_*` folders |
| Comparison table (manual / IntentSanitizer / ShezGuard) | `docs/ATTACK_MATRIX.md`, "Comparison baselines": attack scripts (emulator API 34, 29) and `IntentSanitizerBaselineTest` (confirmed (emulator, API 24, 29, 33, 34, 36)) |
| H2 and H3 blocked after step 16 | `PathAccessorAgreementTest` (confirmed (emulator, API 24, 34), `*_phase6-fixes`); `ShezGuardEvaluateTest.blocksMatrixParamDotDotSegmentEscapingPathPrefix` (Robolectric-only) |

## README.md, step 17 additions (packaging)

| Claim | Evidence |
|---|---|
| 0.1.0 is published to `mavenLocal` only, not to Maven Central | `./gradlew publishToMavenLocal`; no remote repository or signing configured (`shezguard-core/build.gradle.kts`, `shezguard-lint/build.gradle.kts`) |
| The AAR contains `lint.jar` and the consumer R8 rules | `unzip -l` of `shezguard-core-0.1.0.aar`: `lint.jar`, `proguard.txt` with the three `-keep` rules (step 17, `docs/REPRODUCE.md`) |
| Runtime dependencies are `androidx.core:core:1.9.0` and `kotlin-stdlib:2.0.21` only | the published `.pom` and `.module` (release API and runtime variants list exactly these two) |
| A consumer resolves it from `mavenLocal`, its unit tests pass, the Lint rule fires, an R8-minified build works | consumer project outside the repo (AGP 8.10.1, compileSdk 34): 2 Robolectric tests passed; `ShezGuardUnguardedEntryPoint` on the unannotated exported activity; minified APK on emulator API 34: valid link Allow, traversal and unknown-parameter links Block (step 17, not committed; procedure in `docs/REPRODUCE.md`) |
| Older AGP untested | design statement: only 8.10.1 was available offline (L41) |
| Apache-2.0; no NOTICE needed | `LICENSE` (canonical Apache-2.0 text, SHA-256 `cfc7749b…3d30`); no bundled third-party code |

## Public KDoc

| Class / member | Claim | Evidence |
|---|---|---|
| `ShezGuard.evaluate` | Unregistered entry point blocked | `ShezGuardEvaluateTest.blocksUnknownEntryPointByDefault` (Robolectric-only) |
| `ShezGuard.evaluate` | All violations collected | `ShezGuardEvaluateTest.collectsAllViolationsNotJustTheFirst` (Robolectric-only) |
| `ShezGuard.evaluate` | No public state of the intent modified (was "never modified", **fixed**) | `EvaluateInvariantsTest.inputIntentIsNeverModified`, `ExtrasEvaluateTest.inputIntentAndItsExtrasAreNeverModified`, `SanitizeDropTest.sanitizeNeverModifiesTheCallersIntent` (Robolectric-only); L21 |
| `ShezGuard.evaluate` | Same input, same decision | `EvaluateInvariantsTest.sameInputAlwaysGivesSameDecision`; `ExtrasUnparcelTest.repeatedEvaluationGivesTheSameDecision` (emulators API 24–36) |
| `ShezGuard.evaluate` | Does not throw: `RuntimeException` → `EVALUATION_FAILED`; `StackOverflowError` in the extras read → `EXTRAS_UNPARCEL_FAILED`; other `Error`s propagate | `EvaluateInvariantsTest.evaluateNeverThrowsOnFuzzedIntents` (Robolectric-only, 4000 cases); `DeepNesting*DeviceTest`: confirmed (emulator, API 24, 34), cold process (`*_phase6-cold-process`); `ParserMismatchTest.errorsAreNotCaught` (JVM) |
| `ShezGuard` (class) | Reading extras deserialises them; hostile code runs here (L1, L27) | `ExtrasUnparcelTest` (`[N7s] ... ran 1x`): confirmed (emulator, API 24, 29, 33, 34, 36) |
| `ShezGuard.evaluate(activity, …)` | Reliable sources only `getCallingPackage` / `getLaunchedFromPackage` (API 34+, opt-in); referrer advisory | `CallerIdentityDeviceTest`: confirmed (emulator, API 24, 29, 33, 34, 36); `getLaunchedFromPackage`: confirmed (emulator, API 34, 36) |
| `Decision` | Constructors internal: app code cannot forge an Allow | by construction (`internal` constructors) |
| `Decision` | `toString()` never includes the intent | `DecisionTest.decisionToStringNeverContainsIntentData` (Robolectric-only) |
| `Decision.Allow` / `Sanitize` | Allow carries only SOFT violations; Sanitize at least one REMOVABLE and no HARD | `DecisionTest.allowRejectsHardViolation`, `sanitizeRejectsHardViolation`, `sanitizeRequiresAViolation` (Robolectric-only) |
| `Decision.Sanitize` | Sanitize only removes; never rewrites | as in README above |
| `GuardedUri` | Values decoded once; `+` is a space, `%2B` a literal `+` | `UriCanonicalizerTest` (JVM); differential tests 99/111 (emulators API 24–36) |
| `GuardedUri` | Only declared parameters readable | `ShezGuardEvaluateTest.ignoredUnknownParamIsSignalledButNotReadable` (Robolectric-only) |
| `GuardedUri.toString` | Redacts everything but scheme and declared names | `EvaluateInvariantsTest.noDecisionOutputContainsRawUriOrParamValues` (Robolectric-only) |
| `Violation` / `Field` | No public member returns an undeclared name; not a boundary against reflection | `RawNameExposureTest` (Robolectric-only); reflection caveat: design statement (L33) |
| `ActivityGuard.onCreate` | Allow leaves `getIntent()`; Sanitize replaces it; Block sets `RESULT_CANCELED`, empty intent, `finish()` | `ActivityGuardTest.allowKeepsTheOriginalIntentUnchanged`, `sanitizeReplacesTheActivityIntentWithTheSanitizedCopy`, `blocksPathTraversalLaunchFinishesWithResultCanceled`, `blockResetsAResultSetBeforeTheGuardToCanceledWithoutData` (Robolectric-only) |
| `ActivityGuard.onCreate` | "The platform then skips `onStart` and `onResume` and goes to `onDestroy`" | Robolectric-only (`ActivityGuardTest`); platform behaviour source-read (N14) |
| `ActivityGuard.onNewIntent` | Never reads `getIntent()`; Block changes nothing and does not finish; every `onNewIntent` blocked under `requireReliableIdentity` | `ActivityGuardTest.newIntentEvaluatesTheDeliveredIntentNotGetIntent`, `newIntentBlockIsIgnoredAndTheSessionKeepsItsCheckedState`, `requireReliableIdentityIgnoresEveryNewIntent` (Robolectric-only) |
| `ActivityGuard` | Recreation evaluated every time, no cache | `ActivityGuardTest.recreationIsEvaluatedUnderTheCurrentPolicyNotACachedDecision` (Robolectric-only) |
| `ActivityGuard` | Cannot stop the launch | design statement (L34) |
| `CheckedIntent` | Never wraps a Block; `toString()` excludes the intent | `require` in `init` (by construction); `AuditLeakHardeningTest` (`CheckedIntent.toString`) |
| `GuardedEntryPoint` | Not inherited; missing/empty/exempt blocked; unknown name blocked | `ActivityGuardTest.annotationIsNotInheritedBySubclasses`, `missingAnnotationIsDenied`, `exemptEmptyAndContradictoryAnnotationsAreDenied`, `annotatedNameMissingFromPolicyIsDenied` (Robolectric-only) |
| `GuardedEntryPoint` | Consumer R8 rules keep it; checked on one minified build | emulator API 34, step 12 (L36) |
| `AuditSink` / `AuditEvent` | Exactly once per evaluation, after the decision, on the caller's thread; event immutable and redacted | `AuditWiringTest.*`, `AuditEventTest`, `AuditCanaryTest` (Robolectric-only) |
| `AuditSink` | Sink exceptions swallowed, `Error`s propagate; sink cannot change the decision | `AuditWiringTest.throwingSinkDoesNotChangeTheDecision`, `errorsFromTheSinkPropagate`, `sinkCannotMutateTheDecision` (Robolectric-only) |
| `LogcatAuditSink` | Line format, levels, flood cap, thread-safe | `LogcatAuditSinkTest.*` (Robolectric-only) |
| `intentPolicy` / DSL | Every check listed in SPEC 7 (rules 1–16) | `PolicyDslTest.*` (JVM); `@DslMarker`: `everyBuilderCarriesTheDslMarker` (JVM) plus the one-off compiler check recorded in SPEC 7 |
| `EntryPointPolicy` | Defaults are the most restrictive choice | `PolicyModelTest.entryPointDefaultsAreMostRestrictive` (JVM) |
| Policy collections | Unmodifiable copies (step 16, H6); data classes alias when built directly (L45) | `PolicyImmutabilityTest` (Robolectric-only); `PolicyHardeningTest.observesDirectlyConstructedDataClassesAliasTheCallersCollection` |
| `HostPattern` | Lowercase ASCII only; lookalikes never match; `subdomainsOf("com")` rejected; public suffixes not detected (L5) | `PolicyModelTest.hostRejectsCyrillicLookalike`, `hostRejectsUppercase`, `subdomainsOfRejectsBareTopLevelDomain` (JVM); `UriPolicyValidatorTest.blocksPunycodeLookalikeHost` (JVM) |
| `PathPattern` | Patterns cannot express `//`, dot segments, `%`, `\`; prefix ends with `/` | `PolicyModelTest.pathPatternRejectsTraversalAndDotSegments`, `pathPatternRejectsEncodingBackslashAndDuplicateSlash`, `prefixMustEndWithSlashToKeepSegmentBoundary` (JVM) |
| `ParamType.Url` | Rejects `javascript:`, `data:`, `//host`, `https:host`, userinfo; scheme and exact host; no non-default port; no own escapes (L17) | `ShezGuardEvaluateTest.blocksJavascriptUrlInRedirectParam`, `blocksProtocolRelativeRedirectParam`, `blocksOpenRedirectViaUrlParam` (Robolectric-only); `CanonicaliserHardeningTest.holdsSchemeAndAuthorityTricks`; demo t2b, t3 blocked (matrix) |
| `ParamType.Uuid`, `Digits`, `OneOf` | Formats as stated; empty values rejected | `UriPolicyValidatorTest.acceptsUuidInEitherCaseAndLeavesItUnchanged`, `blocksSignedHexAndExponentNumbers`, `enumMatchingIsExactAndCaseSensitive`, `blocksEmptyValueForEveryType` (JVM) |
| `CharClass` | Each class's accepted and rejected examples | `CharClassTest.*` (JVM) |
| `ExtrasRule` | Size limits are approximations (keys, lengths), not Parcel size | design statement (L28) |
| `ExtraType` | Parcelable/Serializable/Bundle deliberately absent | by construction (enum) |
| `Nested.Deny` | Any nested Intent blocks; framework-Parcelable caveat (H5, L26) | `NestedIntentTest.denyIsTheDefault`, `blocks*` (emulators API 24–36); `NestedIntentHardeningTest.observesIntentInsideFrameworkParcelableIsRemovedNotReportedAsNested` |
| `Nested.AllowSanitized` | Only under listed keys, only after `IntentSanitizer` | `NestedIntentTest.blocksNestedIntentUnderUnlistedKey`, `forwardedNestedIntentIsTheSanitizerOutputNotTheOriginal` (emulators API 24–36) |
| `NestedIntentSanitizer` | Rejections become violations, not exceptions; not reimplemented | `NestedIntentTest.intentSanitizerExceptionBecomesViolation` (emulators API 24–36); by construction (wraps `IntentSanitizer`) |
| `Caller.AllowedPackages` | Advisory unless reliable; every current signer must be listed | `CallerAndroidTest.multiSignerCallerNeedsEverySignerListed`, `rotatedOutSigningKeyIsNotAccepted` (Robolectric-only); device cases L30 |
| `Caller.RequireVerifiedDomain` | A fact about the domain, not proof the intent came through a verified link | design statement (L3); `DomainVerificationDeviceTest` (emulator API 33, 34, 36) |
| `Limits` | Defaults 2048 / 256 / 64 parameters; `maxUriLength` at most 8192, `maxParameters` at most 256, rejected at build; parameter cap applied before any `Uri` accessor (**fixed** wording; numbers chosen, not derived) | `PolicyModelTest.limitsRejectNonPositiveValues`, `PolicyDslTest.rejectsOutOfRangeNumbers` (JVM); `ParameterFloodTest` (JVM; no accessor touched); cost: `ResourceExhaustionHardeningTest.measuresH8FloodsAfterTheParameterCap` (JVM), `docs/results/2026-11-18_Pixel_8_api34_phase6-h8-{cap,before,after}/` (emulator, indicative only) |
| `Threshold`, `ScoreWeights` | Range checks; score only adds Block; default weights design choices | `PolicyModelTest.threshold*`, `WeightedScorerTest.*`, `ScoreWeightsTest` (JVM) |

No claim in the audited scope remains without an evidence pointer or an explicit "design statement" / "not verified"
label.
