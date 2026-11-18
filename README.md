# ShezGuard

ShezGuard is a Kotlin Android library that validates the Intents and deep links an app receives at its entry points
against a per-entry-point policy, before the app uses them. For each intent it returns an explainable decision: Allow,
Sanitize (remove the parts the policy does not allow) or Block, with every reason listed as a stable code. A build-time
Android Lint rule checks that every exported or `BROWSABLE` activity names a policy entry point.

It is the proof of concept for an MSc cybersecurity research article. Correctness, explainability and stated limits
matter more here than features.

## Status

- **Research prototype, pre-1.0, not published.** No release exists on Maven Central or any other repository. The API
  may still change.
- Activities only (v1). `ShezGuard.evaluate` accepts any `Intent`, but the Activity helper, the demo app and the
  evaluation cover activities. Services, receivers and providers are out of scope (the Lint rule lists exported ones).
- Known limitations: `docs/LIMITATIONS.md` (L1–L47, with an index and per-item status). Hardening review and fixes:
  `docs/HARDENING.md`.

## Install

Until step 17 the only supported way is a **Gradle project dependency** on a local checkout: copy or include
`:shezguard-core` (and `:shezguard-lint`, which it ships as its Lint rule) in your build, then

```kotlin
// settings.gradle.kts
include(":shezguard-core", ":shezguard-lint")

// app/build.gradle.kts
dependencies { implementation(project(":shezguard-core")) }
```

No Maven publication is configured yet, so `publishToMavenLocal` is not available either. Requirements: minSdk 24;
`androidx.core:core` 1.9.0 (the only runtime dependency, for `IntentSanitizer`), which needs compileSdk ≥ 33 in the
consuming app; the Lint rule targets AGP 8.10.1 (see "Build-time coverage check").

## Minimal usage

```kotlin
val policy = intentPolicy {
    entryPoint("product") {
        allowSchemes("https")                       // also makes a data URI required
        allowHosts("example.com")                   // exact hosts; subdomains only via subdomainsOf(...)
        path { prefix("/product/") }                // or anyPath(); one of them is mandatory
        param("id") { digitsOnly(maxLength = 10); required() }
    }
}

when (val d = ShezGuard.evaluate(intent, policy, "product")) {
    is Decision.Allow    -> show(d.data?.param("id"))   // read data from the Decision, never intent.data
    is Decision.Sanitize -> show(d.data?.param("id"))   // forward d.sanitizedIntent if needed
    is Decision.Block    -> finish()                    // d.violations lists every reason
}
```

`intentPolicy {}` checks the policy when it is built and throws one `PolicyDefinitionException` listing every
problem. Build it in a unit test so mistakes fail there.

## Threat model (summary)

The attacker is another installed app, or a web page or message that triggers a deep link (SPEC section 2). In scope:
1. intent redirection through a nested intent in an extra;
2. deep-link parameter abuse (injection, path traversal, oversized or malformed values, attacker URLs);
3. open redirect through a parameter;
4. unverified or hijackable deep links;
5. malformed Bundles that crash the app or trigger unsafe unparcelling;
6. encoding evasion (case, percent-encoding, double encoding, Unicode lookalikes, control characters).

Out of scope: malware inside the app, a compromised OS, attacks before app code runs, network attacks, reverse
engineering. How each in-scope threat fares against the demo app is in `docs/ATTACK_MATRIX.md`; several are only
partly covered (see "What ShezGuard does not do").

## The policy model in short

An `intentPolicy` is a set of named entry points; an intent for a name that is not defined is blocked
(`ENTRY_POINT_UNKNOWN`). Each entry point has:
- **data rule:** `Forbidden` (default), `Required` (set by `allowSchemes`) or `Optional`;
- **URI rules:** schemes, exact hosts (or `subdomainsOf`), non-default ports, path patterns (exact, prefix ending in
  `/`, or `anyPath()`), fragment allowed or not;
- **parameters:** declared names with one type each (digits, `oneOf`, UUID, a bounded string of a character class, or
  a URL with its own scheme and host allow-list); unknown parameters `Block` (default), `Drop` or `Ignore`; repeated
  parameters blocked unless allowed;
- **extras:** allowed keys with a primitive, `String` or array type and size limits; everything else is removed;
- **nested intents:** `Deny` (default) or `AllowSanitized(keys, IntentSanitizer)`;
- **caller:** `Any` (default), `allowedPackages { ... }` (advisory unless the identity source is reliable) or
  `requireVerifiedDomain()`;
- **limits and score:** URI length (default 2048, at most 8192), parameter value length (default 256), number of
  query parameters (default 64, at most 256), and a soft-signal score with a block threshold (default 70).

Outcome rule: any HARD violation blocks; otherwise a soft score at or above the threshold blocks; otherwise any
REMOVABLE violation gives Sanitize (it only removes, never rewrites); otherwise Allow. All violations are collected,
not just the first. Details: `docs/SPEC.md` sections 4–6.

## Reading deep link data

Read URI data from the `Decision`, never from `getIntent().getData()`. `GuardedUri` exposes only the parameters your
policy **declares**. Parameters kept under `Unknown.Ignore` are not readable through it, but they **remain in the
original intent** (`Decision.Allow.intent`), so code that reads `getIntent()` directly still sees them
(`docs/LIMITATIONS.md` L20). Use `Unknown.Drop` to have them removed from a sanitized copy. Android's own query
accessors disagree with each other about `+` (L11); `GuardedUri` follows `Uri.getQueryParameter`.

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
  launch intent again. So the guard (and its policy) **must not come from fields that a DI framework
  injects during `super.onCreate`**, because they would not exist yet when the guard runs (which frameworks
  inject there, Hilt for example, was not checked in this project: L34). Use a property of your
  `Application`, as above, or a top-level `val`.
- **ShezGuard cannot prevent the launch.** It runs inside your app after the OS has started the
  activity and possibly brought its task to the front. It only controls whether your app uses the
  intent's data.
- **Run deep link handling after the guard.** Navigation's `handleDeepLink`, a Compose `NavHost`
  with deep links, and `addOnNewIntentListener` listeners must only see the checked intent: create
  them after the guard in `onCreate`, and in `onNewIntent` pass `checked.intent`
  (`navController.handleDeepLink(checked.intent)`). ShezGuard cannot enforce this ordering, and where
  Navigation and `ComponentActivity` read the intent was **not verified** here (`docs/LIMITATIONS.md` L35).
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
- `assembleRelease` runs `lintVital<Variant>`, which by AGP's documentation checks **Fatal** issues only, so by
  default ShezGuard's Errors would **not** stop a release build. (AGP's documented behaviour; not run in this
  project.)
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

## What ShezGuard does not do

Each item links to its limitation; none of these is solved by ShezGuard.
- **It does not prevent the launch.** It runs inside your app after the OS has started the activity; it only decides
  whether your app uses the intent's data (L34).
- **It does not make a value safe for a sink.** It checks shape and character class. SQL injection through a printable
  value and path traversal through a printable or single-encoded file name were **not prevented** in the demo
  (`docs/ATTACK_MATRIX.md` t2a, t2c, t6; L37). Sinks with path-parameter semantics may see a different path (L47).
- **It does not stop deserialisation side effects.** It must read extras to find nested intents, so a hostile
  `Parcelable` or `Serializable` runs inside ShezGuard first (L1, L27; matrix row 5b). A native crash during that read
  cannot be caught (L40), nor can `OutOfMemoryError` (L28).
- **It does not prove who the caller is.** Most launches carry no reliable identity; the referrer is set by the caller
  (L3, L30, L44).
- **It does not check** the incoming intent's selector, ClipData or URI-grant flags (L26), numeric extra values (L38),
  opaque URIs such as `mailto:` (L10), internationalised hosts (L7) or IPv6 hosts (L9).
- **It does not prevent link hijacking** (threat 4); the Lint rule only advises (matrix t4; L41).
- **The Lint rule does not prove the guard is called** on every path (L4, L41).
- **Its cost still grows quickly with the number of query parameters.** The count is capped (default 64, at most
  256) because Android's `Uri.getQueryParameter` costs about the cube of the number of value-less parameters; links
  with more parameters are blocked (`PARAM_TOO_MANY`). Raising the cap raises the worst case (L46).

## Tested API levels

Instrumented tests ran on emulators at **API 24, 29, 33, 34 and 36** only (arm64 images, `docs/results/README.md`). No
physical device and no OEM build was tested. JVM tests run under Robolectric (SDK 24, 29, 31, 34 depending on the
test). Every result in the docs carries a label: **confirmed (emulator, API N)**, **Robolectric-only**, or
**source-read only (AOSP, not run)** (`docs/PAPER_NOTES.md`). The step 16 fixes were re-run on API 24 and 34 only.

## Comparison with `IntentSanitizer` and with manual validation

From the demo app's attack runs and the `IntentSanitizerBaselineTest` (`docs/ATTACK_MATRIX.md`, "Comparison
baselines"). The IntentSanitizer column is a test with the tightest allow-list it can express, confirmed (emulator,
API 24, 29, 33, 34, 36); manual validation exists for one entry point only (`ManualCheckActivity`, attack t6).

| Attack | Manual validation | `IntentSanitizer` alone | ShezGuard |
|---|---|---|---|
| t1 nested intent to a private activity | n/a | prevented (if the nested intent is sanitized too) | blocked |
| t2a SQL injection in a parameter | n/a | not prevented | not prevented |
| t2b `file:` / `data:` URL parameter | n/a | not prevented | blocked |
| t2c path traversal in a parameter | n/a | not prevented | not prevented |
| t2d oversized `note` extra | n/a | prevented | blocked |
| t2d huge `copies` value | n/a | prevented only with a value predicate | not prevented (L38) |
| t3 open redirect parameter | n/a | not prevented | blocked |
| t4 link hijack | n/a | n/a | not prevented |
| t5 unknown Parcelable class | n/a | not prevented (the app crashes) | blocked, no crash |
| 5b deserialisation gadget | n/a | not prevented | not prevented |
| t6 raw `../` | rejected | not prevented | not prevented |
| t6 `%2e%2e%2f` | bypassed | not prevented | not prevented |
| t6 `%252e%252e%252f` | bypassed | not prevented | blocked |

In short: `IntentSanitizer` cannot see query parameters or their encoding; it is enough or stronger for nested
intents, extras size and numeric value bounds. ShezGuard adds URL-typed parameters, double-encoding detection and
unparcelling failures without a crash. Neither prevents SQL injection through a printable value, traversal through a
printable file name, the deserialisation gadget or link hijacking. The step 15 review and step 16 fixes add two
protections not in this table (`docs/HARDENING.md`): a path that `getPath()` reads as `//other.host` is blocked
(H2), and `..;` path segments are blocked (H3).

## Further reading

`docs/SPEC.md` (design), `docs/LIMITATIONS.md`, `docs/ATTACK_MATRIX.md`, `docs/HARDENING.md`, `docs/BENCHMARK.md`
(overhead, emulator, indicative only), `docs/CLAIMS_AUDIT.md` (every claim in this README and the public KDoc, with
its evidence).
