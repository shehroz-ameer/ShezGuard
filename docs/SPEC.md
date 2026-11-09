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
- risk threshold mapping score to Allow / Sanitize / Block (soft signals only, see section 5).

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
- Maximum parameter length: 256 characters (overridable per parameter).

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
- **Soft tier.** The score decides the outcome only for soft / advisory signals, such as
  caller hints and unknown parameters under `Unknown.Ignore`. This prevents weights from
  bypassing deny by default.
- Removable violations (section 4.1) produce Sanitize unless a hard violation or the soft
  score produces Block.

### 5.2 Score and thresholds [DECIDED]
- Severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, each with a documented default weight.
- Score is the sum of soft-signal weights, capped at 100 (range 0..100).
- `score >= block` gives Block; else `score >= sanitize` gives Sanitize; else Allow.
- The policy is validated when built: `0 <= sanitize < block <= 100`.
- The decision lists which signals contributed and their weights.

## 6. Canonicalisation (internal, heavily tested)
- Lowercase scheme and host. Reject empty or non-ASCII hosts unless explicitly allowed.
- **[DECIDED]** Split the URI into components first, then percent-decode each component
  once. Never decode the whole URI before splitting (that would turn `%2F`, `%3F`, `%23`
  into real delimiters). An encoded `/` or `\` inside a path segment is Block.
- Percent-decode once; if the result still contains `%XX`, flag double encoding and Block.
  (Known false positives, see `docs/LIMITATIONS.md`.)
- Reject control characters, null bytes, backslashes in paths, `..` segments (raw and encoded).
- Normalise path separators and duplicate slashes. **[DECIDED]** If the raw URI differs from
  the canonical one in more than scheme / host case, record a low-severity violation; the
  app must read data from the `Decision`, never from `getIntent()`.
- Enforce maximum URI and parameter lengths (section 4.2).
- Reject userinfo (`user:pass@host`) tricks.
- **[DECIDED]** Use a small pure-Kotlin parser (JVM-testable). A Robolectric differential
  test compares it with `android.net.Uri` on accepted inputs; if the two disagree, Block.
- **[DECIDED]** Choose and document one rule for `+` versus `%20` in query values.
- **[DECIDED]** Lookalike hosts (including `xn--` punycode) are handled by exact host
  matching. Lookalikes in parameter values are handled by each rule's character set.

## 7. Public API sketch
```kotlin
val policy = intentPolicy {
    entryPoint("product") {
        data(Data.Required)
        allowSchemes("https")
        allowHosts("example.com")
        path { prefix("/product/") }
        param("id") { digitsOnly(maxLength = 10); required() }
        unknownParams(Unknown.Block)
        nestedIntents(Nested.Deny)
        caller(Caller.Any)
        threshold(block = 70, sanitize = 30)
    }
}

when (val d = ShezGuard.evaluate(intent, policy, "product", callerInfo)) {
    is Decision.Allow    -> proceed(d.intent)
    is Decision.Sanitize -> proceed(d.sanitizedIntent)
    is Decision.Block    -> finishWith(d.violations)
}
```
Package: `com.shezguard.core`.
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
