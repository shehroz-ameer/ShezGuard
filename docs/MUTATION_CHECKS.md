# Mutation checks

Hand-written mutants: a deliberate, plausible bug is put into one security-relevant line, the
relevant tests are run, and the code is restored byte for byte. A mutant is **caught** when at
least one test fails. This shows that specific tests would notice specific bugs. It is not a
coverage measure and does not claim the suites catch every bug.

How to run them: `scripts/mutation/README.md`. All results are Robolectric-only (JVM), like the
tests they exercise.

**Provenance.** Steps 10 and 13 were run with `scripts/mutation/run_mutants.py`, and the exact edits are in
`scripts/mutation/step10_activity_guard.py` and `scripts/mutation/step13_*.py`. Steps 8 and 9 were done by hand before the script
existed; only the descriptions recorded in `docs/LIMITATIONS.md` and `docs/PAPER_NOTES.md`
survive. The exact edits, the full list of tests that failed, and the number of SDKs are **not
recorded** and cannot be reconstructed. For steps 1–7 no mutation checks are recorded.

## Steps 1–7
No mutation checks recorded in the docs or commit messages. Whether any were run is **unknown**.

Related, but not mutation checks:
- Step 5b: a fixed-seed fuzz test asserts `EVALUATION_FAILED` never occurs on its corpus
  (SPEC 5.3).
- Step 5b: PAPER_NOTES N4 argues that the parser-agreement check (c)1 alone would have missed the
  crafted `Uri` parcel and that (c)2 blocks it. That is a design argument shown by
  `CraftedUriParcelTest`; no record says (c)2 was removed and the test re-run.

## Step 8: caller signals
Source: `docs/PAPER_NOTES.md` N11, `docs/LIMITATIONS.md` L31.

| Mutant | Broke | Result | Caught by |
|---|---|---|---|
| The `getExtras() == null` guard removed from `ActivityCallerSource`, so `getReferrer()` is called when the caller's intent has extras | Reading the system referrer unparcels the caller's Bundle (N11) | caught on SDK 24, 29, 31, 34 | `CallerAndroidTest.systemReferrerIsNotReadWhenItWouldUnparcelTheCallersExtras` |

## Step 9: audit sink and raw names
Source: `docs/LIMITATIONS.md` L33. Recorded only as "the test catches …" / "are all caught". Per
mutant, the exact edit and failing assertion are **not recorded**. `AuditCanaryTest` runs on
SDK 34 only, `RawNameExposureTest` on the default SDK (34).

| Mutant | Broke | Result | Caught by |
|---|---|---|---|
| Raw undeclared parameter/extra names copied into the event | Attacker text in `AuditEvent` | caught | `AuditCanaryTest` |
| Entry point name not validated (no `<invalid>` replacement) | App-supplied name logged as given, unchecked | caught | `AuditCanaryTest` |
| Sink exception logged | Exception message (with canary) in logcat | caught | `AuditCanaryTest` |
| Evaluation exception logged | Exception message in logcat | caught | `AuditCanaryTest` |
| Debug log of the data URI | Raw URI in logcat | caught | `AuditCanaryTest` |
| Caller package placed in a declared field | Package name in the event | caught | `AuditCanaryTest` |
| `Field` raw name public again | Undeclared name reachable through a public getter | caught | `RawNameExposureTest` |
| Extra key public again | Same, for extras | caught | `RawNameExposureTest` |
| `internal` without `@JvmSynthetic` | Raw name reachable as a public JVM method | caught | `RawNameExposureTest` |
| `declaredName` ignoring `declared` | Undeclared name returned as declared | caught | `RawNameExposureTest` |

## Step 10: Activity helper
Target `ActivityGuard.kt`; tests `ActivityGuardTest` on SDK 24, 29, 31, 34 (debug variant).

**Round 1** (2026-11-12, an ad-hoc script; same edits as the definitions file except d3, which was
run separately). Every mutant was caught except **(e)**, which survived. A new `Activity` already
starts with `mResultCode = RESULT_CANCELED` and `mResultData = null` (`Activity.java` 810–811 (24),
953/956 (34)), so the test could not tell whether the guard sets the result. Fix (author decision):
`PresetResultActivity` sets `RESULT_OK` with data in its initializer, and
`blockResetsAResultSetBeforeTheGuardToCanceledWithoutData` checks that a Block resets it (with an
allowed launch as control).

**Round 2** (2026-11-12, `run_mutants.py scripts/mutation/step10_activity_guard.py`, after the
fix). Baseline green with 108 test cases (27 tests × 4 SDKs); restored byte for byte (SHA-256
verified). Every listed test failed on all 4 SDKs.

| Mutant | Change | Result | Caught by |
|---|---|---|---|
| a1 | `onCreate` Block calls `setIntent` with the blocked intent | caught | `blocksPathTraversalLaunchFinishesWithResultCanceled`, `missingAnnotationIsDenied`, `exemptEmptyAndContradictoryAnnotationsAreDenied`, `annotationIsNotInheritedBySubclasses`, `recreationIsEvaluatedUnderTheCurrentPolicyNotACachedDecision` |
| a2 | `onNewIntent` Block calls `setIntent` with the blocked intent | caught | `newIntentBlockIsIgnoredAndTheSessionKeepsItsCheckedState` |
| b | A blocked `onNewIntent` finishes the activity | caught | `newIntentBlockIsIgnoredAndTheSessionKeepsItsCheckedState`, `newIntentOnUnannotatedActivityIsDeniedWithoutFinishing`, `requireReliableIdentityIgnoresEveryNewIntent`, `skippingSuperOnNewIntentDoesNotThrowAndActivityStaysUsable` |
| c1 | `onCreate` Sanitize does not replace `getIntent()` | caught | `sanitizeReplacesTheActivityIntentWithTheSanitizedCopy`, `rotationReevaluatesSanitizedIntentAsAllowWithIdenticalCanonicalData`, `processDeathRedeliversTheRawIntentAndItIsSanitizedAgain` |
| c2 | `onNewIntent` Sanitize does not replace `getIntent()` | caught | `newIntentSanitizeReplacesTheActivityIntentWithTheSanitizedCopy` |
| d1 | `onCreate` caches its decision in the guard, per activity class | caught | `rotationReevaluates…`, `processDeathRedelivers…`, `recreationWithoutReliableIdentityIsBlockedUnderEnforcingPolicy`, `blockedRecreationDoesNotRestoreFrameworkFragments`, `blockResetsAResultSetBeforeTheGuardToCanceledWithoutData` |
| d2 | `onCreate` caches its decision in the guard, per `Intent` object | caught | `processDeathRedelivers…`, `recreationWithoutReliableIdentity…` |
| d3 | `onCreate` caches its decision in a static field, per activity class | caught | `recreationIsEvaluatedUnderTheCurrentPolicyNotACachedDecision` and 13 others (see note) |
| e | A blocked `onCreate` does not call `setResult(RESULT_CANCELED)` | caught (round 2; **survived round 1**) | `blockResetsAResultSetBeforeTheGuardToCanceledWithoutData` |
| f | `onNewIntent` evaluates `activity.intent` instead of its argument | caught | `newIntentEvaluatesTheDeliveredIntentNotGetIntent`, `newIntentAllowReplaces…`, `newIntentSanitizeReplaces…`, `newIntentBlockIsIgnored…`, `skippingSuperOnNewIntent…`, `everyGuardCallEmitsExactlyOneAuditEvent` |

Notes:
- **d1, d2 vs `recreationIsEvaluatedUnderTheCurrentPolicyNotACachedDecision`.** That test builds a
  new guard for the new policy, so it cannot see a cache held inside a guard. It is the targeted
  test for d3 (a static cache), and it catches d3 when run alone (round 1, 4/4 SDKs). The other
  recreation tests catch d1 and d2.
- **d3 breaks many unrelated tests** because a static cache outlives each test inside the same
  Robolectric sandbox, so decisions leak between tests. Its long list of catching tests says more
  about that leak than about test strength.
- **Selection.** Only `ActivityGuardTest` was run. `AuditCanaryTest`'s guard test was not part of
  the selection.

## Step 14: wiring after the move to `src/sharedTest`
Run 2026-11-17 with `scripts/mutation/run_mutants.py`, JVM (Robolectric) only, debug variant.
- Step 10 mutants **a1** and **e** re-run after the runner switch: both caught by the same tests as
  recorded above, target restored byte for byte. `ActivityGuardTest` was not moved.
- No earlier recorded mutant is caught by a moved class, so a new one was added
  (`scripts/mutation/step14_shared_wiring.py`), target `AndroidExtras.kt`:

| Mutant | Change | Result | Caught by |
|---|---|---|---|
| w1 | A nested intent left inside `IntentSanitizer`'s output is not denied (the `leavesNestedIntent` branch removed) | caught (SDK 24, 29, 34) | `NestedIntentTest.blocksDoublyNestedIntentLeftBySanitizer` (now in `src/sharedTest`) |

The runner located `NestedIntentTest` under `shezguard-core/src/sharedTest/java` (75 cases), and the
target was restored byte for byte.

## Step 13: build-time coverage check (Lint rule)
Targets in `:shezguard-lint`: `ShezGuardDetector.kt` (coverage), `GuardCallHeuristics.kt` (call order and
result use), `DeepLinkDetector.kt` (threat 4 advice). Tests: lint-tests on the JVM (each test runs Lint in
lint-tests' default modes, including partial analysis). Definitions:
`scripts/mutation/step13_coverage.py`, `step13_guard_calls.py`, `step13_deep_link.py`. Every run started
from a green baseline and restored the target byte for byte (SHA-256 verified).

**Round 1** (2026-11-16, without `--no-watch-fs`): c7, c8 and c10 were reported **SURVIVED**. Each was
caught when run again, both by hand (c10) and with the runner (`--only c7,c8,c10`). The test runs had
used the unmutated classes: Gradle's file-system watching apparently missed a write that followed a
restore within seconds. The runner now passes `--no-watch-fs` (`scripts/mutation/README.md`). This
failure mode can only produce false survivors. g1 survived round 1 as well, for a real reason (see
below).

**Round 2** (2026-11-16, `--no-watch-fs`, after two tests were added:
`flagsGuardAfterBareIntentPropertyRead` and `flagsGuardAfterGetIntentCallInJava`):

| Mutant | Change | Result | Caught by |
|---|---|---|---|
| c1 | Implicit export (intent filter, targetSdk < 31) not detected | caught | `CoverageDetectorTest.flagsImplicitlyExportedActivityBelowApi31` |
| c2 | `BROWSABLE` filters ignored | caught | `flagsBrowsableActivityEvenWhenNotExported`, `flagsExportedBrowsableActivityOnce` |
| c3 | `exempt = true` treated as covered without checking for a name | caught | `flagsExemptAnnotationThatAlsoNamesAnEntryPoint` |
| c4 | Empty name accepted | caught | `flagsEmptyNameWithoutExemption` |
| c5 | Any annotated name treated as declared by the policy | caught | `flagsAnnotatedNameMissingFromPolicy`, `noPolicyFoundWithCheckDependenciesIsAnError`, `noPolicyFoundWithoutCheckDependenciesIsUnverifiable`, `nonConstantEntryPointNameMakesMissingNameUnverifiable` |
| c6 | Non-constant `entryPoint` names do not downgrade a missing name (Error instead of Warning) | caught | `nonConstantEntryPointNameMakesMissingNameUnverifiable` |
| c7 | `checkDependencies` ignored: no policy found is always a Warning | caught (round 1: false SURVIVED) | `noPolicyFoundWithCheckDependenciesIsAnError` |
| c8 | Dependency activities treated as the app's own | caught (round 1: false SURVIVED) | `activityFromDependencyIsReportedOnlyAsDependencyEntryPoint` |
| c9 | Unannotated activities not reported | caught | `flagsExplicitlyExportedActivityWithoutAnnotation`, `flagsImplicitlyExportedActivityBelowApi31`, `flagsBrowsableActivityEvenWhenNotExported`, `flagsExportedBrowsableActivityOnce`, `flagsExportedAliasOfUnannotatedActivity`, `flagsUnannotatedJavaActivity` |
| c10 | `android:permission` no longer exempts a service/receiver/provider | caught (round 1: false SURVIVED) | `exportedServiceWithoutPermissionIsInformationalOnly` |
| c11 | Guard call inside an exempt activity not reported | caught | `GuardCallDetectorTest.flagsGuardCallInsideExemptActivity` |
| g1 | Kotlin `intent` property reads before the guard ignored | **SURVIVED** (both rounds) | none: see note |
| g2 | `super.onCreate` / `super.onNewIntent` before the guard ignored | caught | `flagsGuardAfterSuperOnCreate`, `flagsGuardAfterSuperOnNewIntent` |
| g3 | Order comparison inverted | caught | 7 tests, including `acceptsGuardFirstInOnCreateAndOnNewIntent` |
| g4 | `!!` on the guard result counted as a null check | caught | `flagsNotNullAssertedGuardResult` |
| g5 | Any use of the stored result counts as a null check | caught | `flagsStoredGuardResultNeverNullChecked` |
| g6 | Explicit `getIntent()` calls before the guard ignored | caught | `flagsGuardAfterGetIntentCallInJava` |
| g7 | Both `getIntent` branches removed | caught | `flagsGuardAfterGetIntentRead`, `flagsGuardAfterBareIntentPropertyRead`, `flagsGuardAfterGetIntentCallInJava` |
| d1 | `BROWSABLE` not required | caught | `DeepLinkDetectorTest.ignoresCustomSchemeWithoutBrowsable` |
| d2 | Custom schemes not reported | caught | `flagsHijackableCustomSchemeLink`, `flagsEachCustomSchemeOnceInMixedFilter` |
| d3 | https without `autoVerify` also reported (duplicates the built-in `AppLinkWarning`) | caught | `leavesHttpsLinkWithoutAutoVerifyToBuiltInAppLinkWarning` |
| d4 | `autoVerify="false"` accepted | caught | `flagsHttpsLinkWithAutoVerifyFalse` |

Notes:
- **g1 survives because the code is redundant, not because a test is missing.** In Kotlin, a read of
  `intent` is detected by both branches: the `getIntent()` call branch and the `intent` property
  branch. g6 removes the call branch, and only the Java test fails. g1 removes the property branch, and
  nothing fails. g7 removes both, and both Kotlin tests fail. Both branches are kept, because how UAST
  represents a synthetic property may differ between Lint versions. That reason is a precaution and
  was not tested on another version.
- **Names in the table** are `CoverageDetectorTest`, `GuardCallDetectorTest` or `DeepLinkDetectorTest`,
  according to the mutant's letter (c, g or d), except c11, which is caught in `GuardCallDetectorTest`.
- **Not mutated:**
  - the source-manifest location fallback, which lint-tests never reach (L41);
  - the alias and nested-class name handling;
  - `ShezGuardIssueRegistry`, whose severities are pinned by `ShezGuardIssueRegistryTest`, not
    mutated.

### Demo negative control (real Gradle build; the only evidence for the source-mapping fallback)
This mutates the rule's **input**, not the rule: one annotation is removed from the demo app, and Lint
must fail the build at the activity's manifest line. In a real Gradle build, Lint does not map
merged-manifest elements back to source, so this run is the only evidence for the rule's fallback
lookup. No lint-test reaches it (`docs/LIMITATIONS.md` L41).

Procedure, from the repository root, on macOS (`sed -i ''`; with GNU sed use `sed -i`). The working
tree copy of the file must be unmodified, because `git checkout` restores it:

```sh
F=app/src/main/java/com/shezguard/router/demo/SearchActivity.kt
git diff --quiet -- "$F" || { echo "$F has local changes; stop"; exit 1; }
shasum -a 256 "$F"                                     # record the hash
sed -i '' '/^@GuardedEntryPoint("search")$/d' "$F"     # remove the annotation line
grep -c 'GuardedEntryPoint("search")' "$F"             # expect 0
./gradlew :app:lintProtectedDebug --no-watch-fs; echo "exit=$?"   # expect exit=1, "aborting build"
python3 -I -c "
import xml.etree.ElementTree as E
for i in E.parse('app/build/reports/lint-results-protectedDebug.xml').getroot().iter('issue'):
    if i.get('id') == 'ShezGuardUnguardedEntryPoint':
        l = i.find('location'); print(i.get('severity'), l.get('file'), l.get('line'))
"                                                      # expect: Error .../app/src/main/AndroidManifest.xml 44
git checkout -- "$F"                                   # restore
shasum -a 256 "$F"                                     # expect the recorded hash
git status --short -- "$F"                             # expect no output
./gradlew :app:lintProtectedDebug --no-watch-fs        # expect success again (refreshes the report)
```

Expected and observed result (2026-11-16, AGP 8.10.1, run twice: before and after `checkDependencies =
true` was set in `:app`): `exit=1`, "Lint found errors in the project; aborting build",
`Error app/src/main/AndroidManifest.xml 44` (line 44 is `SearchActivity`'s `<activity` element), message
"`SearchActivity` is exported (`android:exported="true"`) and has a BROWSABLE intent filter but has no
`@GuardedEntryPoint`. …". The hash after restoring was the recorded
`0ab519f616e03863ca17224ae64b2bff5d3b4618c510cc9a518c0786fd9e2920`, and `git status` was clean.

- **First run:** the annotation line was blanked rather than deleted, and the file was restored from a
  copy. Same result.
- **Before the fallback existed:** the same run reported the issue at the `app` directory with no
  line. That is how the missing mapping was found.

## Step 16: fixes for the step 15 hardening findings (`docs/HARDENING.md`)

One mutant per new rule: each removes the rule, and the test that the fix moved into the normal suite must fail.
Run with `scripts/mutation/run_mutants.py` (JVM/Robolectric only), 2026-11-18.

| Mutant | Script | Change | Result | Caught by |
|---|---|---|---|---|
| h2 | `step16_h2_get_path.py` | `getPath()` no longer compared in `ParserMismatch` (segments only), so `//` is a soft signal again | caught | `PathAccessorAgreementTest.blocksNetworkPathReferenceThatOnlyGetPathSees` |
| h1a | `step16_h1_stack_overflow.py` (by hand, device) | `AndroidExtras.valueAt` (the `Bundle.get` read site) no longer catches `StackOverflowError` | **caught (emulator, API 34)**: `DeepNestingEvaluateDeviceTest`, `DeepNestingOnNewIntentDeviceTest` threw `StackOverflowError`. Survived (emulator, API 24): there `keySet()` overflows first, so `h1c`'s site catches it | device tests |
| h1b | same | `sanitizeNested` (`IntentSanitizer.sanitize` on a nested intent) no longer catches `StackOverflowError` | **caught (emulator, API 34 and API 24)**: `DeepNestingNestedIntentDeviceTest` | device tests |
| h1c | same | `read()` (the `keySet()` read site) no longer catches `StackOverflowError` | **caught (emulator, API 24)**: `DeepNestingEvaluateDeviceTest`, `DeepNestingOnNewIntentDeviceTest`. Survived (emulator, API 34): `keySet()` leaves List values lazy on API 33+ | device tests |
| h3 | `step16_h3_matrix_dot.py` | The part before `;` no longer counted as a dot segment in `UriCanonicalizer.checkSegment` | caught (JVM) | `UriCanonicalizerTest.blocksMatrixParamDotDotSegment`, `blocksMatrixParamSingleDotSegment`, `ShezGuardEvaluateTest.blocksMatrixParamDotDotSegmentEscapingPathPrefix` |
| h6a | `step16_h6_policy_copies.py` | `IntentPolicy.entryPoints` is the mutable map from `associateBy` again | caught (JVM) | `PolicyImmutabilityTest.builtPolicyCollectionsRejectMutationThroughACast` |
| h6b | same | `EntryPointPolicy.hosts` keeps the caller's set (no copy) | caught (JVM) | `PolicyImmutabilityTest.laterChangesToTheCallersCollectionsDoNotReachThePolicy` |
| h6c | `step16_h6_dsl_copies.py` | The DSL builds `ParamType.OneOf` from a mutable set again | caught (JVM) | `PolicyImmutabilityTest.builtPolicyCollectionsRejectMutationThroughACast` |

H1 mutants are device-only: the proving tests live in `src/androidTest`, because overflow tests never run under
Robolectric (standing rule, `docs/HARDENING.md`), and `run_mutants.py` runs JVM tests only. Procedure (2026-11-18,
emulators Pixel_8 API 34 and ShezGuard_API_24): record the SHA-256 of `AndroidExtras.kt`
(`4886c3cbba7de7dcb743095c78d47f92f08d6a0af2929fd5ef90b08e48adb43e`), apply one edit from the script, build and install
the test APK, run each `DeepNesting*DeviceTest` class in its own `am instrument` process, copy the original back, and
verify the hash. All six restores were byte-identical. Each catch site is needed on at least one API level; no mutant
survived on both. **A first attempt was void:** its edits also deleted the `}` closing the preceding catch block, so
no mutant compiled. The stale clean APK stayed installed and "passed". The driver now refuses to run a mutant whose
build or install failed (BUILD ERROR, never counted as caught).
