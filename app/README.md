# `:app`: ShezGuard demo app (DELIBERATELY VULNERABLE)

> **Warning.** This app is deliberately vulnerable. Install it only on an **emulator**. Never install
> it on a phone you use, never publish it, never upload it to any store. The `vulnerable` flavor is
> marked `android:testOnly="true"` so it cannot be installed without `adb install -t` and Google Play
> rejects it. It has no INTERNET permission, and all of its data is fake.

It is the demonstration target for the attack matrix (`docs/ATTACK_MATRIX.md`): one exported entry
point per threat in `docs/SPEC.md` section 2. Every vulnerability is marked in the code with a
comment `VULNERABLE (threat N): ...`.

## Flavors
| Flavor | `versionName` | What differs |
|---|---|---|
| `vulnerable` | `1.0-vulnerable` | `src/vulnerable/.../guard/EntryGuard.kt`: a pass-through, plus `testOnly` |
| `protected` | `1.0-protected` | `src/protected/.../guard/EntryGuard.kt` runs ShezGuard's `ActivityGuard` with the app-level policy in `src/protected/.../guard/DemoPolicy.kt` (step 12) |

Both flavors share the `applicationId` `com.shezguard.router` and **all** other code, so every attack
targets the same package and the same sinks. Install one flavor at a time.

**The vulnerable flavor has `:shezguard-core` on its classpath and carries the same
`@GuardedEntryPoint` annotations (in the shared `src/main`), but never calls the library**: its
`EntryGuard` is a pass-through, so the annotations have no effect there.

The one deliberate difference from step 12 on: in the protected flavor, `EntryGuard` also decides
how parameters are read (from ShezGuard's `Decision`, as the library requires, instead of
`Uri.getQueryParameter` on the raw intent). Activities read data and extras only through the
`Incoming` object that `EntryGuard` returns, never through `getIntent()`.

## Entry points
Each demo activity carries `@GuardedEntryPoint("<name>")` (name in parentheses below); `MainActivity`
is `@GuardedEntryPoint(exempt = true)`; `InternalAdminActivity` is not exported and has none. The
protected policy per entry point, and why, is in `docs/ATTACK_MATRIX.md` ("Policy the predictions
assume") and in `DemoPolicy.kt`.

| Threat | Activity | Input | Vulnerability |
|---|---|---|---|
| 1 | `ForwardActivity` (`forward`) | extra `next` (an Intent) | launches the nested Intent; reaches the non-exported `InternalAdminActivity` |
| 2 | `SearchActivity` (`search`) | `https://shezguard.example/search?q=` | SQL built by concatenation |
| 2 | `PreviewActivity` (`preview`) | `https://shezguard.example/preview?url=` | URL loaded into a WebView (JavaScript and file access on) |
| 2 | `FileViewerActivity` (`file`) | `https://shezguard.example/file?name=` | path built from the parameter |
| 2 | `NoteActivity` (`note`) | extras `note`, `copies` | unbounded; `note.repeat(copies)` exhausts the heap |
| 3 | `RedirectActivity` (`redirect`) | `https://shezguard.example/redirect?next=` | opens any URL |
| 4 | `LinkActivity` (`login`) | `shezdemo://login?token=`, `https://shezguard.example/login?token=` | custom scheme and https without `autoVerify`: another app can receive the token |
| 5 | `ProfileActivity` (`profile`) | extra `profile` (Serializable) | deserialised without checks; `LegacyProfile.readObject` has a side effect (5b) |
| 6 | `ManualCheckActivity` (`manual`) | `https://shezguard.example/manual?name=` | hand-written check for a raw `..`, bypassed by encoding |

Fake data (created by `DemoApp` on every start): `demo.db` with hidden rows `CANARY-HIDDEN-ROW-*`,
`files/secret.txt` with `CANARY-SECRET-7f3a`, and `files/public/readme.txt`.

## Build types
| Build type | Minified | Audit log to logcat | Use |
|---|---|---|---|
| `debug` | no | yes (`BuildConfig.AUDIT_LOGCAT`) | the attack and benign runs |
| `release` | no | no | not used by the demo |
| `minified` | yes (R8) | yes | **TEST-ONLY. Never ship it.** A release build minified with R8, signed with the debug key, audit logging on, and marked `testOnly` (`src/minified/AndroidManifest.xml`). It exists only to check that R8 keeps `@GuardedEntryPoint` (`docs/LIMITATIONS.md` L36) and that every script gives the same result as the debug build (step 12). |

In the protected flavor, `AUDIT_LOGCAT` installs ShezGuard's redacted `LogcatAuditSink` with
`minOutcome = ALLOW`: one line per decision under the tag `ShezGuard` (outcome, entry point, violation
codes and fields, never values). The vulnerable flavor ignores it.

`app/proguard-rules.pro` keeps the whole `LegacyProfile` class. The usual Serializable keep rules are
not enough for a class the app never constructs (step 12; `docs/LIMITATIONS.md` L40).

`app/src/testProtected/.../DemoPolicyTest.kt` (Robolectric) builds the policy, checks that every
annotation names an entry point of the policy, and replays the URI and extras parts of the attacks
and benign controls through `ShezGuard.evaluate`: `./gradlew :app:testProtectedDebugUnitTest`.

## Install (emulator)
```sh
./gradlew :app:installVulnerableDebug   # or :app:installProtectedDebug
./gradlew :attacker:installDebug
# or with adb directly (test-only APKs need -t):
adb install -t app/build/outputs/apk/vulnerable/debug/app-vulnerable-debug.apk
```
```sh
# test-only minified protected build (step 12):
./gradlew :app:assembleProtectedMinified
adb install -t app/build/outputs/apk/protected/minified/app-protected-minified.apk
```
Then run `scripts/attacks/*.sh` (attacks) and `scripts/attacks/b*.sh` (benign controls); see
`scripts/attacks/README.md`.
