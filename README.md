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

## Activity helper (optional)

`ActivityGuard` does the calls above for you, finds the entry point name from an annotation, and
finishes safely on Block. The core API works without it.

```kotlin
class App : Application() {
    val guard = ActivityGuard(appPolicy)   // build it from code; see "Order" below
}

@GuardedEntryPoint("product")
class ProductActivity : AppCompatActivity() {
    private val guard get() = (application as App).guard

    override fun onCreate(savedInstanceState: Bundle?) {
        val checked = guard.onCreate(this)                  // 1. first, BEFORE super.onCreate
        super.onCreate(checked?.let { savedInstanceState }) // 2. on Block, restore no saved state
        if (checked == null) return                         // 3. Block: the activity is finishing
        setContentView(R.layout.product)
        show(checked.data?.param("id"))                     // read data here, not from intent.data
    }

    override fun onNewIntent(intent: Intent) {
        val checked = guard.onNewIntent(this, intent) ?: return // Block: ignored; no super call
        super.onNewIntent(checked.intent)
        show(checked.data?.param("id"))
    }
}
```

| | Allow | Sanitize | Block |
|---|---|---|---|
| `onCreate` | `getIntent()` unchanged | `getIntent()` = sanitized copy | `RESULT_CANCELED`, `getIntent()` = empty `Intent()`, `finish()`; returns `null` |
| `onNewIntent` | `getIntent()` = the new intent | `getIntent()` = sanitized copy | nothing changes, the activity keeps running; returns `null` |

- **You must use the result.** `null` means Block: return immediately. `@CheckResult` makes Android
  Lint warn when the result is ignored, but that is a warning, not a compiler error: code that
  ignores the result, or reads `getIntent()` before the guard, still compiles.
- **Order: the guard runs before `super.onCreate`**, because `super.onCreate` restores fragments
  and saved state that may read `getIntent()`, and after process death `getIntent()` is the raw
  launch intent again. So the guard (and its policy) **must not come from DI-injected fields of the
  activity**: Hilt, for example, injects them during `super.onCreate`, too late. Use a property of
  your `Application`, as above, or a top-level `val`.
- **ShezGuard cannot prevent the launch.** It runs inside your app after the OS has started the
  activity and possibly brought its task to the front. It only controls whether your app uses the
  intent's data.
- **Run deep link handling after the guard.** Navigation's `handleDeepLink`, a Compose `NavHost`
  with deep links, and `addOnNewIntentListener` listeners must only see the checked intent: create
  them after the guard in `onCreate`, and in `onNewIntent` pass `checked.intent`
  (`navController.handleDeepLink(checked.intent)`). ShezGuard cannot enforce this ordering
  (`docs/LIMITATIONS.md` L35).
- **A blocked `onNewIntent` is ignored, not finished**, so another app cannot end the user's running
  session with one bad intent. The user gets no visible response unless you add one.
- **Every creation is evaluated, including recreation.** No decision is cached, so a recreation can
  block where the first launch was allowed (a changed policy, or a lost reliable caller identity).
  Under `allowedPackages(requireReliableIdentity = true)`, every `onNewIntent` is blocked.
- **The annotation.** `@GuardedEntryPoint("name")` on the activity's own class (it is not inherited).
  A missing or empty annotation, or `@GuardedEntryPoint(exempt = true)`, is blocked
  (`ENTRY_POINT_NOT_ANNOTATED`); a name your policy does not define is `ENTRY_POINT_UNKNOWN`. The
  library's consumer R8 rules keep the annotation; if a build strips it, the activity is blocked,
  never let through. A check on a minified build is still to come (step 12).

See `docs/SPEC.md` (section 7.2) and `docs/LIMITATIONS.md` (L34–L36).

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
