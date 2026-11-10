# ShezGuard: design specification

Status: draft by the author, refined after the orientation review (`docs/ORIENTATION.md`).
Decisions taken in that review are marked **[DECIDED]**. Open questions are marked **[DECIDE]**.

## 1. Problem
Android apps expose entry points (exported components, deep links) that accept
data from untrusted callers. Developers are told to validate that data manually,
and the platform provides partial mitigations, but there is no declarative,
app-side layer that (a) validates URI and parameter content, (b) handles nested
intents, (c) reasons about caller trust, (d) produces an explainable decision,
and (e) can be checked at build time for coverage of all entry points.

## 2. Threat model
Attacker: another installed app, or a web page / message that triggers a deep link.
Asset: the app's sensitive sinks (WebView loads, database queries, file paths,
`startActivity` calls, account or payment actions).

In scope:
1. Intent redirection: an untrusted nested Intent in an extra is launched by the app.
2. Deep link parameter abuse: injection (SQL, JS), path traversal, oversized or
   malformed values, attacker-controlled URLs loaded into a WebView or used for redirects.
3. Open redirect via a deep link parameter.
4. Unverified or hijackable deep links (custom schemes, missing App Links verification).
5. Malformed Bundles that crash the app or trigger unsafe unparcelling.
6. Encoding evasion: case tricks, percent-encoding, double encoding, unicode lookalikes,
   control characters.

Out of scope: malware inside the app, compromised OS, attacks before app code runs,
network-layer attacks, reverse engineering.

**[DECIDED] Component scope for v1.** `ShezGuard.evaluate()` accepts any `Intent`, but the
Activity helper, the demo app and the evaluation cover Activities only. Services and
Receivers are out of v1.

## 3. Related work to position against (cite properly, verify details)
- AndroidX `IntentSanitizer` (allow-list sanitising of an intent). Closest competitor.
- Android 16 default intent redirection hardening, and Android's deep link guidance.
- System-level Intent Firewall work (needs OS privileges, not usable by normal apps).
- Static analysers and pentest tools (detect offline, do not enforce at runtime).
  Differentiators to defend: URI and parameter policy, declarative multi-entry-point policy,
  caller trust model, explainable scoring, build-time coverage check.

## 4. Policy model
A `IntentPolicy` is a set of named `EntryPointPolicy` objects. Each entry point policy has:
- data rule **[DECIDED]**: `Required`, `Forbidden` or `Optional`. A missing URI skips the URI
  stages only when the rule allows it; otherwise it is a violation.
- allowed schemes, hosts, optional path patterns (exact or prefix, no free regex on host)
  - **[DECIDED]** hosts match exactly (after lowercasing). Subdomains are allowed only by an
    explicit opt-in such as `subdomainsOf("example.com")`. No IDN conversion.
  - **[DECIDED]** non-default ports are rejected unless the policy allows them.
  - **[DECIDED]** fragments are rejected unless the policy allows them.
  - **[DECIDED]** path patterns are mandatory for an entry point that accepts URI data
    (`Data.Required` or `Data.Optional`): it must declare at least one exact or prefix
    pattern, or an explicit `anyPath()`. The DSL rejects the policy otherwise. In the model,
    an empty pattern list matches no path; `PathPattern.AnyPath` matches any canonical path.
    Prefix patterns must end with `/` so matching stops at a segment boundary.
- parameter rules: name, type (digits, enum, UUID, bounded string, URL-allowlisted), max length, required or optional
  - **[DECIDED]** repeated parameters (`?id=1&id=2`) are blocked by default (parameter pollution).
  - **[DECIDED]** `URL-allowlisted` canonicalises the nested URL with the same canonicaliser,
    then requires an allowed scheme and an exact host match. It rejects `javascript:`,
    `data:`, protocol-relative `//host` and `https:host` forms.
- unknown-parameter behaviour **[DECIDED]**:
  - `Block` (default): unknown parameter is a violation.
  - `Drop`: unknown parameter is removed, producing a Sanitize decision.
  - `Ignore`: unknown parameter stays in the intent and is recorded as a low-severity signal.
- nested intent rule: `Deny` (default) or `AllowSanitized(IntentSanitizer)`.
  **[DECIDED]** the policy model stays free of Android types; the `IntentSanitizer` is held
  in a small Android-side wrapper and called through its `sanitize(intent, penalty)` overload,
  so its rejections become violations instead of exceptions. `IntentSanitizer` is wrapped,
  never reimplemented.
- extras rule: allowed keys and types, size limit.
  **[DECIDED]** "size limit" means a limit on the number of keys and on the length of strings
  and arrays. It is an approximation, not a measured Parcel size.
- caller rule **[DECIDED]**: `Any`, `RequireVerifiedDomain` (DSL: `requireVerifiedDomain()`,
  replaces `VerifiedAppLinkOnly`), `AllowedPackages(set + signature digests)`. See section 8.
- block threshold: the soft-signal score at or above which the intent is blocked
  (section 5.2). **[DECIDED]** there is no sanitize threshold.

Semantics: policies are evaluated deterministically. Same input gives same decision.
**[DECIDED]** "Input" means (intent, policy, entry point name, caller info, SDK level).

### 4.1 What Sanitize may change [DECIDED]
Sanitize may only **remove**:
- unknown query parameters (under `Unknown.Drop`)
- extras that the extras rule does not allow
- nested intents, through `IntentSanitizer` (under `AllowSanitized`)

Sanitize **never rewrites** any value: not a parameter value, scheme, host, path, port,
component, action, type or flags. If removing something cannot fix a violation, the
decision is Block.

### 4.2 Default limits [DECIDED]
- Maximum URI length: 2048 characters (overridable per entry point).
- Maximum parameter value length: 256 characters (overridable per parameter).
- Maximum parameter name length: 64 characters, fixed (step 4 decision).

## 5. Decision pipeline
1. Canonicalise the URI (see section 6). If canonicalisation fails, Block.
2. Structural checks: data rule, scheme, host, port, path, fragment.
3. Parameter checks against rules.
4. Extras and nested intent checks (wrap `IntentSanitizer` where relevant). Reading extras
   can throw on unparcelling failure: catch, record `EXTRAS_UNPARCEL_FAILED`, never crash.
5. Caller signals collected (best effort, see limitations).
6. Risk score from weighted signals (weights configurable, defaults documented).
7. Produce `Decision` with a list of `Violation(code, entryPoint, field, severity)`.
   Codes are stable identifiers (e.g. `URI_DOUBLE_ENCODING`) so they can be asserted in
   tests and used in the paper. All violations are collected, not just the first.

### 5.1 Two-tier decision [DECIDED]
- **Hard tier.** Structural and content violations always Block, regardless of weight:
  canonicalisation failures, scheme / host / port / path / fragment / data-rule failures,
  parameter rule failures, repeated parameters, unknown parameters under `Unknown.Block`,
  nested intents under `Nested.Deny`, and anything Sanitize cannot remove (section 4.1).
- **Removable tier.** Violations Sanitize can fix by removal (section 4.1).
- **Soft tier.** Advisory signals, such as caller hints, domain verification and unknown
  parameters under `Unknown.Ignore`. Only these feed the score. This prevents weights from
  bypassing deny by default.

**Outcome rule**, applied in this order:
1. Any HARD violation: **Block**.
2. Soft-signal score `>= block` threshold: **Block**.
3. Any REMOVABLE violation: **Sanitize** (remove those parts).
4. Otherwise: **Allow**, with any soft signals listed in the decision.

### 5.2 Score and threshold [DECIDED]
- Severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, each with a documented default weight.
- Score is the sum of soft-signal weights, capped at 100 (range 0..100).
- There is one threshold, `block`, in `1..100` (default 70). There is **no sanitize
  threshold**: Sanitize can only remove parts, and soft signals (caller hints, domain
  verification) have nothing to remove, so a score-driven Sanitize would be meaningless.
- The decision lists which signals contributed and their weights.

## 6. Canonicalisation (internal, heavily tested)
- Lowercase scheme and host. Reject empty or non-ASCII hosts unless explicitly allowed.
- **[DECIDED]** Split the URI into components first, then percent-decode each component
  once. Never decode the whole URI before splitting (that would turn `%2F`, `%3F`, `%23`
  into real delimiters). An encoded `/` or `\` inside a path segment is Block.
- Percent-decode once; if the result still contains `%XX`, flag double encoding and Block.
  (Known false positives, see `docs/LIMITATIONS.md`.)
- Reject control characters, null bytes, backslashes in paths, `..` segments (raw and encoded).
  **[DECIDED]** single `.` segments (raw and encoded) are rejected the same way as `..`.
- **[DECIDED]** Reject Unicode format characters (general category Cf: bidi controls,
  zero-width characters, and the rest) in every component, after decoding. This includes
  query values (see `docs/LIMITATIONS.md`).
- Normalise path separators and duplicate slashes. **[DECIDED]** If the raw URI differs from
  the canonical one in more than scheme / host case, record a low-severity violation; the
  app must read data from the `Decision`, never from `getIntent()`.
- Enforce maximum URI and parameter lengths (section 4.2).
- Reject userinfo (`user:pass@host`) tricks.
- **[DECIDED]** Use a small pure-Kotlin parser (JVM-testable). A Robolectric differential
  test compares it with `android.net.Uri` on accepted inputs; if the two disagree, Block.
- **[DECIDED]** (changed in step 4) Query parameter names must match `[A-Za-z0-9_.-]{1,64}`
  in the raw URI, before decoding; anything else, including `+` and `%`, is
  `PARAM_NAME_INVALID` (hard). Not configurable in v1 (`docs/LIMITATIONS.md` L16).
- **[DECIDED]** `+` decodes to a space in query parameter values, and stays a
  literal `+` in the path. `%2B` always decodes to a literal `+`. This matches what apps
  read through `Uri.getQueryParameter`; the differential test must cover it and fail
  loudly if `android.net.Uri` disagrees.
- **[DECIDED]** Lookalike hosts (including `xn--` punycode) are handled by exact host
  matching. Lookalikes in parameter values are handled by each rule's character set.

## 7. Public API sketch
```kotlin
val policy = intentPolicy {
    entryPoint("product") {
        allowSchemes("https")          // also switches data to Data.Required
        allowHosts("example.com")
        path { prefix("/product/") }   // or anyPath(); one of them is mandatory
        param("id") { digitsOnly(maxLength = 10); required() }
        unknownParams(Unknown.Block)
        nestedIntents(Nested.Deny)
        caller(Caller.Any)
        threshold(block = 70)
    }
}

when (val d = ShezGuard.evaluate(intent, policy, "product", callerInfo)) {
    is Decision.Allow    -> proceed(d.intent)
    is Decision.Sanitize -> proceed(d.sanitizedIntent)
    is Decision.Block    -> finishWith(d.violations)
}
```
Package: `com.shezguard.core`.

**[DECIDED]** DSL rules (step 5):
- An entry point's data rule defaults to `Data.Forbidden`. Calling `allowSchemes(...)`
  switches it to `Data.Required` unless `data(...)` was set explicitly.
- An entry point that accepts URI data must declare a path pattern or `anyPath()`.
- **[DECIDED]** (step 5) The DSL lives in `com.shezguard.core.policy` (`intentPolicy { }`).
  Build-time checks collect every problem and throw one `PolicyDefinitionException`
  (an `IllegalArgumentException`) when the policy is built, usually at app start; apps
  should build their policy in a unit test. Each message says where, what and how to fix.
  The checks:
  1. at least one entry point; unique, valid names;
  2. a data-accepting entry point (`Required`/`Optional`) needs schemes,
  3. hosts,
  4. and a path pattern or `anyPath()`;
  5. `anyPath()` cannot be combined with path patterns;
  6. URI rules (schemes, hosts, ports, paths, fragment, params, `unknownParams`,
     `allowRepeatedParams`) are an error when the effective data rule is `Forbidden`,
     whether set explicitly or by default; the fix is `allowSchemes(...)` or `data(...)`;
  7. a single-valued option (`data`, `threshold`, `unknownParams`, `nestedIntents`,
     `limits`, `extras`, the caller rule) set twice is an error, not an override;
  8. `allowedPackages` needs packages, each with at least one SHA-256 digest; digests may
     be written in either case or as keytool-style colon pairs and are normalised to
     64 lowercase hex characters;
  9. each parameter has exactly one type, a unique name in `[A-Za-z0-9_.-]{1,64}`, and a
     usable `oneOf` list;
  10. an unset `maxLength` defaults to the entry point's `maxParamLength`; an explicit one
      may not exceed it;
  11. `url { }` needs a scheme and a host;
  12. a nested-intent key may not also be an allowed extra;
  13. numbers in range (threshold `1..100`, positive limits and sizes, ports `1..65535`).
- **[DECIDED]** (step 5) `@ShezGuardDsl` (a `@DslMarker`) is on every builder. The compiler
  rejects implicit calls to an outer builder; checked once by hand on 2026-11-10, Kotlin
  2.0.21: `param("id") { allowHosts("x") }`, `entryPoint("a") { entryPoint("b") { } }` and
  `path { anyPath() }` each fail with "cannot be called in this context with an implicit
  receiver".

Also provide an Activity helper (`guardedOnCreate` or lifecycle callback) and an
`AuditSink` interface (default: no-op; optional redacted logcat sink).

## 8. Caller identity (be honest)
`getCallingPackage()` only works for `startActivityForResult`. `getReferrer()` can be
influenced by the caller. Treat caller information as a risk signal, not proof, unless
the entry point uses a signature-protected permission. Document this in LIMITATIONS.md.

**[DECIDED]**
- `AllowedPackages` is a scored (soft) signal by default. It is enforced as a hard rule
  only when the identity source is reliable or the component is protected by a signature
  permission. The decision records which identity source was used.
- `RequireVerifiedDomain` checks whether the app's own domain is verified
  (`DomainVerificationManager`, API 31+; unknown below). It is a fact about the domain plus
  a risk signal, not proof that this intent came through a verified link: any app can send
  an explicit intent with `https` data. Threat 4 is handled mainly by the build-time check
  (section 9), which flags custom schemes and `BROWSABLE` filters without `autoVerify`.

## 9. Build-time coverage check
Goal: fail the build if an exported component, or a component with a BROWSABLE intent
filter, has no registered ShezGuard policy.

**[DECIDED]** Annotation-based: `@GuardedEntryPoint("product")` on the component class,
checked by a custom Android Lint rule in a separate `:shezguard-lint` module (Lint API as
`compileOnly`, so `:shezguard-core` keeps no third-party runtime dependencies).
- Lint reads the merged manifest and the Kotlin source and matches exported components
  (including pre-API 31 implicit export via intent filters) to annotations.
- Explicit exemption is possible (`exempt = true`), e.g. for the launcher activity.
- A unit-test helper checks that every annotated name exists in the `intentPolicy {}` DSL.
- Lint is wired into `check` with `abortOnError` so it actually fails the build.
- Fallback: if the Lint rule costs more than about a day, switch to a registry file checked
  by a Gradle task against the merged manifest, and tell the author.
- Limitation: the check proves a policy is declared, not that `evaluate()` is called.

KSP remains an optional stretch.

## 10. Evaluation plan (not an empirical study)
Show by construction and demonstration, not by large-scale measurement:
1. Attack matrix: each in-scope threat vs blocked / sanitized / not covered, with the
   test name proving it.
2. Demo app (`:app`): vulnerable version vs protected version, with adb attack scripts.
3. Comparison against `IntentSanitizer` alone and manual validation: what each catches.
4. Micro-benchmark of evaluation overhead (median and p95 per intent) on one device or emulator.
5. Optional: run against a small set of known vulnerable apps (DIVA, InsecureBankv2, Ghera)
   only where the app source allows integration. Do not overclaim.

## 11. Deliverables
- `:shezguard-core` library with tests
- `:app` demo app (vulnerable and protected flavours)
- `:shezguard-lint` build-time coverage check (Lint rule; registry-file Gradle task as fallback)
- `scripts/attacks/*.sh` adb attack scripts
- `docs/LIMITATIONS.md`, `docs/ATTACK_MATRIX.md`
- README with usage, threat model summary and limitations
