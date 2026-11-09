# IntentGuard: design specification

Status: draft by the author, to be refined. Open questions are marked **[DECIDE]**.

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

## 3. Related work to position against (cite properly, verify details)
- AndroidX `IntentSanitizer` (allow-list sanitising of an intent). Closest competitor.
- Android 16 default intent redirection hardening, and Android's deep link guidance.
- System-level Intent Firewall work (needs OS privileges, not usable by normal apps).
- Static analysers and pentest tools (detect offline, do not enforce at runtime).
  Differentiators to defend: URI and parameter policy, declarative multi-entry-point policy,
  caller trust model, explainable scoring, build-time coverage check.

## 4. Policy model
A `IntentPolicy` is a set of named `EntryPointPolicy` objects. Each entry point policy has:
- allowed schemes, hosts, optional path patterns (exact or prefix, no free regex on host)
- parameter rules: name, type (digits, enum, UUID, bounded string, URL-allowlisted), max length, required or optional
- unknown-parameter behaviour: `Block` (default) or `Ignore`
- nested intent rule: `Deny` (default) or `AllowSanitized(IntentSanitizer config)`
- extras rule: allowed keys and types, size limit
- caller rule: `Any`, `VerifiedAppLinkOnly`, `AllowedPackages(set + signature digests)`
- risk threshold mapping score to Allow / Sanitize / Block

Semantics: policies are evaluated deterministically. Same input gives same decision.
Define precisely what "sanitize" can change (e.g. drop unknown params) and what it never changes.

## 5. Decision pipeline
1. Canonicalise the URI (see section 6). If canonicalisation fails, Block.
2. Structural checks: scheme, host, path.
3. Parameter checks against rules.
4. Extras and nested intent checks (wrap `IntentSanitizer` where relevant). Reading extras
   can throw on unparcelling failure: catch, treat as suspicious, never crash.
5. Caller signals collected (best effort, see limitations).
6. Risk score from weighted signals (weights configurable, defaults documented).
7. Produce `Decision` with a list of `Violation(code, entryPoint, field, severity)`.
   Codes are stable identifiers so they can be asserted in tests and used in the paper.

## 6. Canonicalisation (internal, heavily tested)
- Lowercase scheme and host. Reject empty or non-ASCII hosts unless explicitly allowed.
- Percent-decode once; if the result still contains `%XX`, flag double encoding and Block.
- Reject control characters, null bytes, backslashes in paths, `..` segments (raw and encoded).
- Normalise path separators and duplicate slashes.
- Enforce maximum URI and parameter lengths.
- Reject userinfo (`user:pass@host`) tricks.

## 7. Public API sketch
```kotlin
val policy = intentPolicy {
    entryPoint("product") {
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

when (val d = IntentGuard.evaluate(intent, policy, "product", callerInfo)) {
    is Decision.Allow    -> proceed(d.intent)
    is Decision.Sanitize -> proceed(d.sanitizedIntent)
    is Decision.Block    -> finishWith(d.violations)
}
```
Also provide an Activity helper (`guardedOnCreate` or lifecycle callback) and an
`AuditSink` interface (default: no-op; optional redacted logcat sink).

## 8. Caller identity (be honest)
`getCallingPackage()` only works for `startActivityForResult`. `getReferrer()` can be
influenced by the caller. Treat caller information as a risk signal, not proof, unless
the entry point uses a signature-protected permission. Document this in LIMITATIONS.md.

## 9. Build-time coverage check
Goal: fail the build if an exported component, or a component with a BROWSABLE intent
filter, has no registered IntentGuard policy. Preferred route within a short timeline:
a custom Android Lint rule or a Gradle task parsing the merged manifest and checking
against policy names declared via an annotation or registry file. KSP is an optional stretch.
**[DECIDE]** annotation-based (`@GuardedEntryPoint("product")`) vs registry file.

## 10. Evaluation plan (not an empirical study)
Show by construction and demonstration, not by large-scale measurement:
1. Attack matrix: each in-scope threat vs blocked / sanitized / not covered, with the
   test name proving it.
2. Sample app: vulnerable version vs protected version, with adb attack scripts.
3. Comparison against `IntentSanitizer` alone and manual validation: what each catches.
4. Micro-benchmark of evaluation overhead (median and p95 per intent) on one device or emulator.
5. Optional: run against a small set of known vulnerable apps (DIVA, InsecureBankv2, Ghera)
   only where the app source allows integration. Do not overclaim.

## 11. Deliverables
- `:shezguard-core` library with tests
- `:sample` app (vulnerable and protected flavours)
- `scripts/attacks/*.sh` adb attack scripts
- `docs/LIMITATIONS.md`, `docs/ATTACK_MATRIX.md`
- README with usage, threat model summary and limitations
- Build-time coverage check (lint rule or Gradle task)
