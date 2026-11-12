# Mutation checks

Hand-written mutants: a deliberate, plausible bug is put into one security-relevant line, the
relevant tests are run, and the code is restored byte for byte. A mutant is **caught** when at
least one test fails. This shows that specific tests would notice specific bugs. It is not a
coverage measure and does not claim the suites catch every bug.

How to run them: `scripts/mutation/README.md`. All results are Robolectric-only (JVM), like the
tests they exercise.

**Provenance.** Step 10 was run with `scripts/mutation/run_mutants.py`, and the exact edits are in
`scripts/mutation/step10_activity_guard.py`. Steps 8 and 9 were done by hand before the script
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
