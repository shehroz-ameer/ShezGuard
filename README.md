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
  ignores the result, or reads `getIntent()` before the guard, still compiles. The ShezGuard Lint
  rule flags the common forms of both (see "Build-time coverage check").
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
  never let through. Checked in step 12 on one R8-minified build of the demo app, on an API 34
  emulator: the annotation survived and no activity was blocked for a missing one (`docs/LIMITATIONS.md` L36).
- **Serializable extras and R8.** If your app accepts `Serializable` extras, keep those classes
  **completely** in your own R8 rules (`-keep class com.example.YourClass { *; }`). The usual
  Serializable rules, which keep only members such as `readObject` and `serialVersionUID`, were not
  enough in step 12. The demo app never constructed its Serializable class itself, so R8 made the
  class abstract and removed `readObject`. Deserialising an instance then crashed the app natively
  (SIGSEGV) while ShezGuard inspected the extras, and ShezGuard cannot catch a native crash. See
  `docs/LIMITATIONS.md` L40.

See `docs/SPEC.md` (section 7.2) and `docs/LIMITATIONS.md` (L34–L36).

## Build-time coverage check (Android Lint)

The library's AAR contains a Lint rule (`lint.jar`, built from `:shezguard-lint` with `lintPublish`).
Lint loads it in modules that depend on ShezGuard. This was verified for a Gradle project dependency
(the demo app, step 13). For a published AAR it is AGP's standard `lintPublish` behaviour, but it was
not tested here because nothing is published yet (step 17). It adds nothing to your runtime or compile
classpath. Run it with
`./gradlew :app:lint<Variant>`. `./gradlew check` runs Lint for the **default variant only**.

| Issue ID | Default severity | Reports | Confidence |
|---|---|---|---|
| `ShezGuardUnguardedEntryPoint` | Error | An activity (or activity-alias) in the merged manifest that is exported, or has a `BROWSABLE` filter, and has no valid `@GuardedEntryPoint`. "Exported" means `android:exported="true"`, or no attribute plus an intent filter while targetSdkVersion < 31. | High. The manifest is read exactly, and the class is matched by name. |
| `ShezGuardUnknownEntryPointName` | Error | An annotated name that no `entryPoint("...")` in an `intentPolicy {}` declares. Raised only when the analysed code proves it: every `entryPoint` argument is a constant, and an `entryPoint` call was found, or `checkDependencies` is on. | High within the analysed modules. |
| `ShezGuardEntryPointNameUnverifiable` | Warning | Like the above, when it cannot be proved: a non-constant `entryPoint(...)` argument, or no `entryPoint` call found with `checkDependencies` off (the policy may be in another module). | Low: the name may well be declared. |
| `ShezGuardInvalidAnnotation` | Error | `exempt = true` together with a name, an empty name without `exempt`, a name the DSL rejects, or a direct `ActivityGuard` call inside an exempt activity. The guard blocks all of these at runtime. | High. |
| `ShezGuardGuardCallOrder` | Error | A direct `ActivityGuard.onCreate` call after `super.onCreate` or after a read of `getIntent()`/`intent` in the same `onCreate`, or `ActivityGuard.onNewIntent` after `super.onNewIntent`. | Medium: compares source order inside one method; branches and helper methods are not followed. |
| `ShezGuardUncheckedGuardResult` | Warning | A guard result stored in a variable that the same method never compares with `null` or uses with `?.`/`?:`, and a result asserted with `!!`. A result ignored completely is left to the built-in `CheckResult` check (Warning). | Low: a syntactic heuristic. |
| `ShezGuardUnverifiableDeepLink` | Warning | A `BROWSABLE` filter with a custom scheme, or an http(s) one with `android:autoVerify="false"` (threat 4). An http(s) filter with **no** `autoVerify` is reported by the built-in `AppLinkWarning` check, which is part of Android Lint, not of ShezGuard. | Advice: Lint cannot know whether a link carries a secret or whether the domain verifies. |
| `ShezGuardDependencyEntryPoint` | Warning | An exported or `BROWSABLE` activity declared by a dependency's manifest. You cannot annotate it. | High that it is reachable; it may be harmless. |
| `ShezGuardUncoveredComponent` | Informational ("Hint") | The app's own exported services, receivers and providers that no `android:permission` protects. ShezGuard v1 covers activities only. Never fails a build. | High that it is exported. |

**When Lint fails your build:**
- `lint<Variant>` (and `check`, which runs Lint for the default variant) fails on any **Error** or
  **Fatal** issue while `abortOnError` is `true`, which is the default. Warnings fail it only with
  `warningsAsErrors = true`.
- `assembleRelease` runs `lintVital<Variant>`. That checks **Fatal** issues only, so by default
  ShezGuard's Errors do **not** stop a release build.
- **Set `checkDependencies = true` in the app module.** It is what makes policy names provable. With it,
  Lint analyses your library modules together with the app, so a `@GuardedEntryPoint` name that no
  `entryPoint("...")` declares is reported as an Error (`ShezGuardUnknownEntryPointName`). Without it,
  the policy might be in a module Lint did not analyse. If no `entryPoint` call is found at all, the
  name is then only a Warning (`ShezGuardEntryPointNameUnverifiable`), which does not fail the build. The demo
  app uses this setting. Its vulnerable flavor has annotations but no policy, and `lintVulnerableDebug`
  fails with 9 such Errors. Without the setting it passed with 9 Warnings (`app/README.md`, "Lint").
- To also make missing coverage stop release builds:

```kotlin
// app/build.gradle.kts
android {
    lint {
        abortOnError = true            // the default; do not turn it off
        checkDependencies = true       // analyse library modules too: makes missing policy names provable Errors
        fatal += setOf(                // also enforced by lintVital on assembleRelease
            "ShezGuardUnguardedEntryPoint",
            "ShezGuardUnknownEntryPointName",
            "ShezGuardInvalidAnnotation",
            "ShezGuardGuardCallOrder",
        )
        error += "CheckResult"         // the built-in check for an ignored guard result (Warning by default)
    }
}
```

- A Lint `baseline` file, `lint.xml`, `ignore`/`disable` or `@SuppressLint` hides findings silently.
  Review any of them that mention a `ShezGuard*` ID.

**What it does not prove.** The check proves that every reachable activity **names** an entry point
your policy declares (or is explicitly exempt). It does not prove that the activity calls the guard,
or `ShezGuard.evaluate`, or acts on the result. The only exception is the call-order and result checks
on a **direct** `ActivityGuard` call inside the same method. A wrapper around the guard, like the demo
app's `EntryGuard`, hides the call from those checks.

**AGP versions.** The rule is compiled against Lint 31.10.1, which belongs to AGP 8.10.1 (Lint version
= AGP version + 23). With an **older** AGP, Lint skips the whole rule and reports only an
`ObsoleteLintCustomCheck` warning, so the coverage check silently stops failing builds. With a newer
AGP, an incompatible API change shows up as a `LintError`. See `docs/LIMITATIONS.md` L41.

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
