# ShezGuard

Work in progress. The full README (usage, threat model, limitations, comparison with
`IntentSanitizer`) is written in step 16 of `docs/PROMPTS.md`.

## Reading deep link data

Read URI data from the `Decision`, never from `getIntent().getData()`:

```kotlin
when (val d = ShezGuard.evaluate(intent, policy, "product")) {
    is Decision.Allow    -> show(d.data?.param("id"))
    is Decision.Sanitize -> show(d.data?.param("id"))   // forward d.sanitizedIntent if needed
    is Decision.Block    -> finish()
}
```

`GuardedUri` exposes only the parameters your policy **declares**. Parameters kept under
`Unknown.Ignore` are not readable through it, but they **remain in the original intent**
(`Decision.Allow.intent`), so code that reads `getIntent()` directly still sees them
(`docs/LIMITATIONS.md` L20). Use `Unknown.Drop` to have them removed from a sanitized copy.

## Caller checks (advisory unless the source is reliable)

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val d = ShezGuard.evaluate(this, intent, Delivery.LAUNCH, policy, "partner")
}

override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    val d = ShezGuard.evaluate(this, intent, Delivery.NEW_INTENT, policy, "partner")
}
```

- **`allowedPackages(requireReliableIdentity = true)` blocks ordinary browser deep links** and
  plain `startActivity` calls. Only a caller that uses `startActivityForResult`, or
  `ActivityOptions.setShareIdentityEnabled(true)` on API 34+, can be identified. Use it for
  app-to-app integrations you control. Without it, an allow-list only adds to the risk score for
  unidentified callers.
- **Forward-result caveat.** `getCallingPackage()` names the app that will receive the result.
  With `FLAG_ACTIVITY_FORWARD_RESULT`, an activity that an allowed app started for result can
  launch yours and forward that result, so the allowed app is reported although another app
  launched yours.
- For `onNewIntent` deliveries no reliable identity is available (`docs/PAPER_NOTES.md` N12).
- An allowed caller that rotates its signing key is blocked until its new key is listed.

See `docs/SPEC.md` (section 8.1) and `docs/LIMITATIONS.md` (L3, L30–L32).

## Audit events

```kotlin
val policy = intentPolicy {
    if (BuildConfig.DEBUG) auditSink(LogcatAuditSink())   // debug builds only
    entryPoint("product") { /* ... */ }
}
```

- Every `ShezGuard.evaluate(...)` call sends **one** redacted `AuditEvent` to the policy's sink,
  after the decision is made: entry point, outcome, violation codes with redacted field labels
  (`param:<undeclared>`), score, threshold and the caller identity source. Never URI or parameter
  values, hosts, extras, package names or certificate digests.
- **The sink runs synchronously on the thread that called `evaluate`**, usually the main thread.
  Keep it fast; hand I/O to your own executor.
- **A sink may be called concurrently from several threads and must be thread-safe.**
- **A sink's exceptions are swallowed deliberately**, without logging, so a broken sink can neither
  change the decision nor crash the app. Report your own failures if you need to know about them.
- `LogcatAuditSink` is intended for **debug builds**: register it only when `BuildConfig.DEBUG`.
  It logs Block decisions by default and caps output at 30 lines per minute.
- Violations never expose an undeclared (attacker-chosen) parameter or extra name. For
  `Field.Param` and `Field.Extra`, `declaredName` gives the name only when it comes from your policy,
  and is `null` otherwise; `toString()` prints `param:<undeclared>` / `extra:<undeclared>`. Both are
  safe to log. The raw intent (`Decision.Allow.intent`, `Decision.Sanitize.sanitizedIntent`) still
  contains everything the caller sent, so never log it.
