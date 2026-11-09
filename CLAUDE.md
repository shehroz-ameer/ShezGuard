# ShezGuard

Kotlin Android library (`:shezguard-core`) plus a demo app (`:sample`). It is the
proof-of-concept for an MSc cybersecurity research article, so correctness,
explainability and honest limitations matter more than feature count.

Read `docs/SPEC.md` before making any design decision. If the spec and your
instinct disagree, ask me instead of choosing silently.

## What it does
A declarative, developer-side layer that validates incoming Intents and deep
links at an app's entry points (Activities, and where relevant Services and
Receivers) against a per-entry-point policy, and returns an explainable
Allow / Sanitize / Block decision.

## Hard rules
- Kotlin only. `explicitApi()` is on: every declaration is deliberately `public` or `internal`.
- `:shezguard-core` has NO third-party runtime dependencies. androidx.core is the only
  allowed one (for `IntentSanitizer`). Test deps (JUnit, Robolectric) are fine.
- minSdk 24. Do not use APIs above that without a guard.
- Deny by default: an entry point with no policy is blocked.
- Collect ALL violation reasons for an intent, not just the first.
- Never log raw intent data, URIs, or extras by default. Logging is opt-in and redacts values.
- Do not reimplement `androidx.core.content.IntentSanitizer`. Wrap it for nested-intent handling.
- Keep pure Kotlin logic (canonicalisation, rule evaluation, scoring) free of Android
  types where practical, so it is unit-testable on the JVM.
- Do not claim a protection the code does not provide. If something cannot be done
  reliably (e.g. caller identity), say so in KDoc and in `docs/LIMITATIONS.md`.

## Workflow
- Small steps, one concern per change. Explain what you changed and why.
- Every validator ships with unit tests named after the attack category it covers
  (e.g. `blocksDoubleEncodedPathTraversal`).
- Before saying a task is done, run `./gradlew :shezguard-core:test` and report the result.
- Do not edit `build.gradle.kts` dependency versions without telling me.
- Do not touch files outside the project, and do not read or print secrets or keystores.
- When you discover a limitation, append it to `docs/LIMITATIONS.md` right away.

## Out of scope
General app hardening, obfuscation, root detection, network security config,
ML-based detection, iOS, Java support beyond what Kotlin interop gives for free.
