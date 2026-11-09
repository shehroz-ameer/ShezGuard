# Prompt sequence for Claude Code

Use these in order, one per session step. After each one: read the diff, run the tests,
commit. If a result surprises you, ask Claude Code to explain it before moving on.

## 0. Orientation (no code yet)
Read CLAUDE.md and docs/SPEC.md. Summarise the project in your own words, list anything
ambiguous or contradictory in the spec, and list the **[DECIDE]** items with your
recommendation for each. Do not write code yet.

## 1. Project and build setup
Check the current structure of the project. Make sure `:shezguard-core` is an Android library
module and `:app` depends on it with `implementation(project(":shezguard-core"))`.
Enable `explicitApi()`, set minSdk 24, add androidx.core, JUnit and Robolectric as test
dependencies. Add one trivial passing test and run `./gradlew :shezguard-core:test`.
Tell me every version you chose and why.

## 2. Core model
In `:shezguard-core`, implement the data model from SPEC section 4 and 5: `Decision`
(Allow, Sanitize, Block), `Violation` with stable string codes, severity, and
the policy classes. Keep them free of Android types where possible. No evaluation logic yet.
Add KDoc to every public declaration.

## 3. Canonicalisation
Implement the canonicaliser from SPEC section 6 as an `internal` pure-Kotlin component.
Write thorough unit tests first: mixed case, single and double percent-encoding, `..` raw
and encoded, null bytes, control characters, backslashes, userinfo tricks, overlong input,
unicode lookalike hosts. Show me the test list before implementing.

## 4. URI and parameter validation
Implement scheme, host and path checks and the parameter rule types (digits, enum, UUID,
bounded string, URL allow-list). Unknown-parameter handling per spec. Collect all violations.
Unit tests per rule and per failure mode, plus tests for several violations at once.

## 5. Policy DSL
Implement the Kotlin DSL from SPEC section 7 (`intentPolicy { entryPoint(...) { ... } }`),
with `@DslMarker` to prevent scope leaks and validation of the policy itself (for example,
reject a policy with no allowed hosts for an https entry point). Tests for the DSL.

## 4b. Evaluator
Implement `ShezGuard.evaluate(...)` running the pipeline in SPEC section 5 for URI and
parameter checks. Deny by default for unknown entry points. Robolectric tests using real
`Intent` and `Uri` objects.

## 6. Extras, Bundles and nested intents
Add extras rules and nested intent handling. Wrap `androidx.core.content.IntentSanitizer`
for the allow-sanitized mode rather than reimplementing it. Handle unparcelling exceptions
safely: catch, record a violation, never crash. Tests for nested intents (explicit and
implicit), oversized extras, unexpected types, and a Bundle that throws on read.

## 7. Risk scoring
Implement the weighted scoring and threshold mapping from SPEC section 5, with defaults
documented in KDoc and overridable per entry point. Keep it deterministic and explainable:
the decision must list which signals contributed and their weights. Tests for threshold edges.

## 8. Caller signals
Implement best-effort caller information (`getCallingPackage`, `getReferrer` where available,
signature digest comparison for `AllowedPackages`). Mark every signal as advisory in KDoc.
Append the limitations to docs/LIMITATIONS.md.

## 9. Audit sink
Add the `AuditSink` interface, a no-op default, and an optional redacted logcat sink.
Verify by test that raw URIs and extras are never emitted by default.

## 10. Activity integration
Provide a small helper (lifecycle callbacks or base-class helper) that evaluates the
incoming intent for an annotated or registered entry point and finishes safely on Block.
Cover `onCreate` and `onNewIntent`. Keep it optional so the core stays usable without it.

## 11. Sample app, vulnerable version
In `:app`, build a deliberately vulnerable app: exported Activity with an https deep link
that loads a parameter into a WebView, one that forwards a nested intent, one that concatenates
a parameter into a SQLite query, and one that reads an unbounded extra. Add comments marking
each vulnerability. Create `scripts/attacks/*.sh` adb commands, one per threat in SPEC section 2.

## 12. Sample app, protected version
Add a product flavour or build variant that applies ShezGuard to the same entry points.
Re-run each attack script and record outcomes in docs/ATTACK_MATRIX.md (attack, vulnerable
result, protected result, test name, notes). Do not mark an attack as blocked unless a test
or script proves it, and list any that remain uncovered.

## 13. Build-time coverage check
Implement the check from SPEC section 9 (annotation + Lint rule in `:shezguard-lint`; registry-file Gradle task only as the agreed fallback) that fails when an exported
or BROWSABLE component has no registered policy. Test it against a sample manifest that
passes and one that fails. Explain the trade-offs of the approach you chose.

## 14. Benchmark
Add a micro-benchmark (Jetpack Microbenchmark or a simple timed loop if Microbenchmark is
impractical) measuring evaluation time for typical and worst-case intents. Report median and
p95 and describe the setup precisely so I can reproduce it.

## 15. Hardening review
Act as a security reviewer of `:shezguard-core`. List bypasses, edge cases and unsafe defaults
you can find, ordered by severity, with a failing test for each one you can demonstrate.
Do not fix anything yet.

## 16. Fix and document
Fix the issues from step 15, one commit each. Then write README.md (usage, threat model
summary, limitations, comparison with IntentSanitizer and manual validation) and finish
docs/LIMITATIONS.md. Do not overstate protection anywhere.

## 17. Packaging
Add maven-publish configuration, an Apache-2.0 or MIT licence, and a CHANGELOG.
Verify with `./gradlew :shezguard-core:publishToMavenLocal` and a consuming test project.

## Standing instructions (repeat if Claude Code drifts)
- Stay within the spec. Ask before adding features or dependencies.
- Tests first for security-relevant code.
- Say what you are unsure about instead of guessing.
- Never weaken a check to make a test pass. Tell me instead.
