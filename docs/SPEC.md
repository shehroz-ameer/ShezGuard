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
- score weights **[DECIDED]** (step 7): per-code overrides of the default weights of SOFT
  signals (section 5.2).

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
   **[DECIDED]** (step 6) This stage always runs, even when the URI stages already block
   (section 5.4).
5. Caller signals collected (best effort, see limitations; section 8.1).
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
> ShezGuard's risk score is a transparent, additive tally of a few advisory signals, compared
> with a fixed threshold. It is not learned, adaptive or statistical, and it does not detect
> attacks: every attack-specific check is a HARD rule that blocks regardless of the score. In v1
> there are six soft signals, mostly about caller identity and domain verification, which cannot
> be established reliably (`docs/LIMITATIONS.md` L3). The score exists so that several individually inconclusive
> signals can combine into a Block in a way a developer can read and tune. With the default
> weights, no single signal blocks, and only two strong (HIGH) signals together reach the default
> threshold. Before caller signals are implemented (step 8), the score cannot change any outcome
> under default settings.

- Severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, each with a documented default weight:
  5, 25, 50, 100 (step 7 lowered `LOW` from 10 to 5).
- **[DECIDED]** (step 7) The default weight of a SOFT code is the default weight of its default
  severity. In v1: `URI_NON_CANONICAL`, `PARAM_UNKNOWN_IGNORED`, `CALLER_UNIDENTIFIED` and
  `DOMAIN_VERIFICATION_UNAVAILABLE` 5; `CALLER_NOT_ALLOWED` and `DOMAIN_NOT_VERIFIED` 50.
  **These defaults are design choices, not empirically derived.** They are chosen so that, at
  the default threshold 70: no single soft signal blocks; one HIGH signal plus every LOW signal
  that can occur with it stays below 70 (50 + 3 x 5 = 65); any two HIGH signals block (100).
  This relies on two pairs never being emitted together: `CALLER_UNIDENTIFIED` /
  `CALLER_NOT_ALLOWED` and `DOMAIN_NOT_VERIFIED` / `DOMAIN_VERIFICATION_UNAVAILABLE`
  (step 8 must prove it). Checked over every emittable subset by
  `WeightedScorerTest.defaultWeightsOverAllEmittableSubsetsOfSoftSignals`.
- **[DECIDED]** (step 7) **Score = the sum over distinct soft codes** of their weights, capped
  at 100 (range 0..100): each SOFT code counts once per evaluation, however many violations it
  has, so that, for example, seven ignored tracking parameters cost one signal, not seven.
  Weights are integers in `0..100`; no rounding.
- There is one threshold, `block`, in `1..100` (default 70). The intent is blocked by the score
  when `score >= block`. A score of 0 never blocks; `block - 1` does not block; `block` and 100
  do. The cap never changes an outcome, because `block <= 100`. There is **no sanitize
  threshold**: Sanitize can only remove parts, and soft signals (caller hints, domain
  verification) have nothing to remove, so a score-driven Sanitize would be meaningless.
- The score can only add a Block: it never turns a Block into Sanitize or Allow, nor a Sanitize
  into Allow, whatever the weights (HARD is checked first; section 5.1).
- **[DECIDED]** (step 7) Weights are overridable per entry point with
  `scoreWeight(code, weight)` in the DSL (`EntryPointPolicy.scoreWeights`, a `ScoreWeights`).
  Only SOFT codes; weight in `0..100`; each code at most once. 0 keeps the signal listed in
  the violations but makes it count for nothing; 100 makes it block on its own.
- The decision lists which signals contributed and their weights: `Decision.score` is a
  `RiskScore` with `total`, `threshold` (the block threshold applied; `null` when no entry point
  policy applied) and `contributions`, one `ScoreContribution(violation, weight, occurrences)`
  per distinct code with a non-zero weight, in order of first occurrence. `violation` is the
  first violation of that code; its `Field` redacts undeclared names, so no raw value appears.

### 5.3 Evaluator, URI and parameter stages (step 5b) [DECIDED]
- **Entry.** `ShezGuard.evaluate(intent, policy, entryPointName)`. The pipeline is pure Kotlin
  (`com.shezguard.core.eval`); only a thin adapter in `com.shezguard.core.android` touches
  `Intent` and `Uri`. In step 5b only `intent.getData()` / `getDataString()` are read, never
  extras; step 6 adds the extras stage (section 5.4).
- **Unknown entry point.** Block with a single `ENTRY_POINT_UNKNOWN` (HARD); the intent is not read.
- **Data rule.** No data URI: `Required` gives `DATA_MISSING`; `Optional` and `Forbidden`
  skip the URI stages. A data URI on a `Forbidden` entry point gives `DATA_FORBIDDEN` only:
  the URI is not canonicalised or examined further. An empty data string is present data
  (`URI_EMPTY`).
- **`URI_PARSER_MISMATCH`.** After canonicalisation succeeds, two checks, each mismatching
  component reported once:
  1. canonical vs `android.net.Uri`: `isHierarchical` true; `getScheme`, `getHost` equal
     after ASCII-only lowercasing; `getPort` equal after mapping `-1` and the scheme default
     to "none"; `getUserInfo` null; `getPathSegments` equal; trailing slash (from `getPath`)
     equal; `getFragment` equal; `getQueryParameterNames` the same set; each value via
     `getQueryParameter` (singular only, L11) equal to the first canonical value.
  2. `android.net.Uri` vs itself: `getAuthority`, `getPath`, `getQuery`, `getFragment` each
     equal `Uri.decode` of the encoded counterpart (crafted parcels, `docs/PAPER_NOTES.md` N4).
- **Reading data.** `Decision.Allow.data` and `Decision.Sanitize.data` are a `GuardedUri`:
  canonical scheme, host, port, path segments, fragment, and values of **declared**
  parameters only. Parameters kept under `Unknown.Ignore` are not readable there, although
  they remain in the original intent. `GuardedUri.toString()` redacts everything except the
  scheme and declared parameter names.
- **Sanitize under `Unknown.Drop`.** The intent is copied with `Intent(Intent)` and only the
  data is replaced, with `setDataAndType(newUri, original.type)`. The new URI string is the
  raw `dataString` with the raw query pieces of dropped names removed; everything else is
  kept byte for byte, and the `?` is removed if no piece remains (method in full:
  `eval/QueryRemoval.kt`). The result is canonicalised and mismatch-checked again; it must
  equal the original canonical URI minus the dropped parameters, otherwise the decision is
  `EVALUATION_FAILED`.
- **Outcome rule** as in 5.1. Until step 7 the score is always 0, so rule 2 never fires.
- **Fail closed.** Any `RuntimeException` during evaluation gives Block with a single
  `EVALUATION_FAILED` (HARD, CRITICAL) violation, with no exception message and no other
  violations. `Error`s are not caught. A fixed-seed fuzz test asserts `EVALUATION_FAILED`
  never occurs on its corpus, so the safety net cannot hide library bugs.

### 5.4 Extras and nested intents (step 6) [DECIDED]
Author approval of the step 6 proposal, 2026-11-11 (`docs/RESPONSE.md`).
- **Reading.** `intent.getExtras()` once (a copy of the parcelled bytes on API 24–34, so the
  caller's Bundle is never unparcelled), then `keySet()` once, then the deprecated
  `Bundle.get(key)` for every key, the only accessor that shows the real type. Nested Bundles
  are read the same way. Each read catches `RuntimeException` only: a failed `keySet()` gives
  one `EXTRAS_UNPARCEL_FAILED` on `Field.Extras` and ends the stage; a failed value gives
  `EXTRAS_UNPARCEL_FAILED` on that key. A failed Bundle is never re-read (`docs/PAPER_NOTES.md`
  N6). An extras failure does not discard the URI violations. No restrictive class loader in
  v1 (revisit in step 14).
- **Order.** The stage always runs, even when the URI stages already block (author decision 1),
  so the violation list is complete. `ENTRY_POINT_UNKNOWN` still reads nothing.
- **Key count.** More than `maxKeys` (default 16) gives `EXTRAS_TOO_MANY` and ends the stage
  before any value is read.
- **Key rule**, per top-level key:
  - allowed key: the value must have exactly the declared `ExtraType` (`STRING_ARRAY` means a
    `String[]`, not an `Object[]` or `CharSequence[]`), else `EXTRA_WRONG_TYPE` (HARD). A
    `null` value counts as absent (author decision 5). Strings longer than `maxStringLength`
    (default 256, `String.length`), arrays longer than `maxArrayLength` (default 64), or any
    `String[]` element longer than `maxStringLength` give one `EXTRA_TOO_LARGE` (HARD) per key.
    String content is not checked;
  - `Nested.AllowSanitized` key: see below;
  - any other key, including a `null` key (reported as `""`): `EXTRA_NOT_ALLOWED` (REMOVABLE).
- **Nested-intent rule**, independent of the key rule: an `Intent`, `PendingIntent` or
  `IntentSender` anywhere in a value (directly, in an object array, `List`, `Map` key or value,
  `SparseArray`, or nested `Bundle`) gives `NESTED_INTENT_DENIED` (HARD), except a single `Intent`
  directly under an `AllowSanitized` key. Search does not descend into an Intent.
- **Depth.** At most `ExtrasRule.MAX_NESTING_DEPTH` = 4 containers inside one extra. A deeper
  container is not read and gives `EXTRAS_TOO_DEEP` (HARD, HIGH; author decision 2).
- **`Nested.AllowSanitized(keys, sanitizer)`.** A single `Intent` under a listed key is passed to
  `IntentSanitizer.sanitize(intent, penalty)`; the penalty messages hold raw values and are
  discarded unread. The result is `NESTED_INTENT_SANITIZED` (REMOVABLE) for **every** such
  intent, even with no penalty, so the app forwards the sanitizer's output (author decision 3),
  unless one of these gives `NESTED_INTENT_DENIED` (HARD): the output's component differs from
  the input's (IntentSanitizer replaced it with `android/java.lang.Void`, a rewrite; author
  decision 4); the sanitizer threw; or the output still holds an `Intent`, `PendingIntent` or
  `IntentSender`. A `PendingIntent`, `IntentSender` or array under a listed key is denied; any
  other non-null value there is `EXTRA_WRONG_TYPE`.
- **Sanitize.** The copy is `Intent(original)` (with the URI change of section 5.3 if any), then
  `replaceExtras(rebuilt)`, where `rebuilt` holds only the values ShezGuard read and checked for
  allowed keys (arrays copied) and the sanitizer's output for nested keys. The rebuilt key set
  is checked after `replaceExtras`; a mismatch gives `EVALUATION_FAILED`. Extras are rebuilt only
  when an extras violation is REMOVABLE; otherwise the copy's extras stay parcelled (N5).

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

when (val d = ShezGuard.evaluate(intent, policy, "product")) {  // callerInfo added in step 8
    is Decision.Allow    -> proceed(d.data)       // read d.data?.param("id"), never intent.data
    is Decision.Sanitize -> proceed(d.data)       // d.sanitizedIntent to forward the cleaned intent
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
  13. numbers in range (threshold `1..100`, positive limits and sizes, ports `1..65535`);
  14. (step 7) `scoreWeight(code, weight)` only for SOFT codes, with a weight in `0..100`, and
      at most once per code.
  15. (step 8) `requireVerifiedDomain()` only on an entry point that accepts an `http`/`https`
      data URI, without other schemes and without `subdomainsOf(...)`.
  16. (step 9) `auditSink(...)` at most once per policy.
- **[DECIDED]** (step 5) `@ShezGuardDsl` (a `@DslMarker`) is on every builder. The compiler
  rejects implicit calls to an outer builder; checked once by hand on 2026-11-10, Kotlin
  2.0.21: `param("id") { allowHosts("x") }`, `entryPoint("a") { entryPoint("b") { } }` and
  `path { anyPath() }` each fail with "cannot be called in this context with an implicit
  receiver".

Also provide an Activity helper (`guardedOnCreate` or lifecycle callback) and an
`AuditSink` interface (default: no-op; optional redacted logcat sink).

### 7.1 Audit sink (step 9) [DECIDED]
Author approval of the step 9 proposal, 2026-11-11 (`docs/RESPONSE.md`).
- **Registration:** on the policy, `intentPolicy { auditSink(sink) ... }`, once (a second call is
  an error, DSL rule 16). Default `AuditSink.NONE`, which does nothing. No global state; the
  `evaluate` signatures are unchanged.
- **Event:** `AuditEvent` is immutable (unmodifiable lists, no Android types): `entryPoint`
  (replaced by `<invalid>` unless it is a valid entry point name), `outcome`, `violations` as
  `AuditViolation(code, field, tier, severity)` where `field` is the redacted `Field.toString()`,
  `scoreTotal`, `threshold` (`null` when no entry point policy applied), `contributions` as
  `AuditContribution(code, weight, occurrences)`, and `callerIdentitySource`. It never carries the
  intent, the `Decision`, `Violation`/`Field` objects, any URI component or parameter value, the
  host, extras, nested intents, package names, certificate digests or exception messages.
- **Raw names** (step 9 follow-up, author decision): `Field.Param` / `Field.Extra` are regular
  classes with explicit `equals`/`hashCode`/`toString`; the raw name is `internal` and
  `@JvmSynthetic`, and the public `declaredName` is non-null only for names from the policy. No
  public member of `Field`, `Violation`, `ScoreContribution`, `RiskScore` or `Decision` returns an
  undeclared name (`RawNameExposureTest`).
- **When:** exactly once per `evaluate` call, on every path (Allow, Sanitize, Block,
  `ENTRY_POINT_UNKNOWN`, `EVALUATION_FAILED`), **after** the decision is complete, synchronously on
  the calling thread. A sink may be called from several threads at once and must be thread-safe.
- **Isolation:** a `RuntimeException` from building the event or from the sink is swallowed
  deliberately, without logging, and the decision is returned unchanged. `Error`s propagate. The
  sink receives only the event, never the decision or the intent.
- **`LogcatAuditSink`:** explicit construction only, intended for debug builds
  (`if (BuildConfig.DEBUG) auditSink(LogcatAuditSink())`). Tag `ShezGuard`; `WARN` for Block,
  `INFO` otherwise; `minOutcome` default `BLOCK`; one line per event:
  `outcome=BLOCK ep=product score=0/70 caller=- violations=[URI_PATH_TRAVERSAL@uri.path, PARAM_UNKNOWN@param:<undeclared>x7]`
  (identical violations grouped as `xN`). At most `maxLinesPerMinute` (default 30) lines per
  60-second window; the rest are counted and reported in one `suppressed=N` line.

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

### 8.1 Caller signals (step 8) [DECIDED]
Author approval of the step 8 proposal, 2026-11-11 (`docs/RESPONSE.md`). Source evidence in
`docs/PAPER_NOTES.md` N11–N13; all of it is source-read or Robolectric-only, **unconfirmed on
device** until step 14.
- **API.** `ShezGuard.evaluate(intent, policy, name)` is unchanged and has no caller source and no
  `Context`. The new overload `ShezGuard.evaluate(activity, intent, delivery, policy, name)` adds
  caller identity and domain verification. The intent and `Delivery` (`LAUNCH` from `onCreate`,
  `NEW_INTENT` from `onNewIntent`) are passed explicitly, because the OS keeps the identity of
  the launch that created the activity (N12).
- **Sources.** Reliable, `LAUNCH` only: `getLaunchedFromPackage()` (API 34+, only if the
  launcher called `ActivityOptions.setShareIdentityEnabled(true)` or shares the app's uid) and
  `getCallingPackage()` (only for `startActivityForResult`; it names the app that receives the
  result, which with `FLAG_ACTIVITY_FORWARD_RESULT` can be an earlier app than the immediate
  launcher). Advisory: `EXTRA_REFERRER` / `EXTRA_REFERRER_NAME`, read from ShezGuard's own copy
  of the extras; and the system referrer through `Activity.getReferrer()`, only for `LAUNCH` and
  only when both the delivered intent and `activity.intent` have `getExtras() == null`, because
  otherwise `getReferrer()` unparcels the caller's Bundle (N11). The `@hide` `getLaunchedFrom*`
  methods on API 31–33 are not used.
- **Certificates.** `GET_SIGNING_CERTIFICATES` with `SigningInfo.getApkContentsSigners()`
  (API 28+), `GET_SIGNATURES` (API 24–27): the caller's **current** signers. Every current
  signer must be in the allow-list for that package; past signers from the signing lineage are
  not accepted, so a key rotation needs an allow-list update. No `<queries>` entry is needed: the
  OS grants implicit visibility of the reliable caller on API 30+ (N13). Advisory packages are
  compared by name only.
- **Codes** (only under `allowedPackages`; `Caller.Any` emits no caller signal), at most one per
  decision:
  - every reliable source is listed with all current signers listed: none;
  - a reliable source fails, or its certificates cannot be read: `CALLER_NOT_ALLOWED_RELIABLE`
    (HARD, fail closed);
  - no reliable source and `requireReliableIdentity = true`: `CALLER_IDENTITY_REQUIRED` (HARD);
  - no reliable source and the advisory source names an unlisted package: `CALLER_NOT_ALLOWED`
    (SOFT);
  - otherwise, including an advisory source naming an allowed package: `CALLER_UNIDENTIFIED`
    (SOFT). A spoofed referrer therefore cannot lower the score below "unidentified".
- **Enforcing mode.** `allowedPackages(requireReliableIdentity = true) { ... }`. It blocks every
  caller without a reliable identity, **including ordinary browser deep links and plain
  `startActivity` calls**. Meant for app-to-app integrations whose callers you control.
- **Domain.** `requireVerifiedDomain()` (API 31+): `DomainVerificationManager
  .getDomainVerificationUserState(packageName)`; verified means the canonical host's state is
  `DOMAIN_STATE_VERIFIED` and `isLinkHandlingAllowed()`. Otherwise `DOMAIN_NOT_VERIFIED`. Below
  API 31, without a `Context`, without the service or state, or on any exception:
  `DOMAIN_VERIFICATION_UNAVAILABLE`. No data URI or a rejected URI: no domain code. At most one
  domain code per decision.
- **DSL checks (rule 15).** `requireVerifiedDomain()` needs a data-accepting entry point with only
  `http`/`https` schemes and may not be combined with `subdomainsOf(...)` (hosts are looked up
  exactly; wildcard hosts are not expanded).
- **Explanation.** `Decision.callerIdentitySource` (`CALLING_PACKAGE`, `LAUNCHED_FROM_PACKAGE`,
  `REFERRER_EXTRA`, `REFERRER_SYSTEM`, `NONE`; `null` when the caller is not looked at). Package
  names and digests never appear in a violation or decision (`Field.CallerSignal`).
- **Not in v1.** A signature-level permission on the component (SPEC 8 above) is enforced by the
  OS, not detected by ShezGuard; ShezGuard does not read the manifest at runtime.

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
