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
| `protected` | `1.0-protected` | `src/protected/.../guard/EntryGuard.kt`: identical pass-through in step 11; ShezGuard's `ActivityGuard` from step 12 |

Both flavors share the `applicationId` `com.shezguard.router` and **all** other code, so every attack
targets the same package and the same sinks. Install one flavor at a time.

The one deliberate difference from step 12 on: in the protected flavor, `EntryGuard` also decides
how parameters are read (from ShezGuard's `Decision`, as the library requires, instead of
`Uri.getQueryParameter` on the raw intent). Activities read data and extras only through the
`Incoming` object that `EntryGuard` returns, never through `getIntent()`.

## Entry points
| Threat | Activity | Input | Vulnerability |
|---|---|---|---|
| 1 | `ForwardActivity` | extra `next` (an Intent) | launches the nested Intent; reaches the non-exported `InternalAdminActivity` |
| 2 | `SearchActivity` | `https://shezguard.example/search?q=` | SQL built by concatenation |
| 2 | `PreviewActivity` | `https://shezguard.example/preview?url=` | URL loaded into a WebView (JavaScript and file access on) |
| 2 | `FileViewerActivity` | `https://shezguard.example/file?name=` | path built from the parameter |
| 2 | `NoteActivity` | extras `note`, `copies` | unbounded; `note.repeat(copies)` exhausts the heap |
| 3 | `RedirectActivity` | `https://shezguard.example/redirect?next=` | opens any URL |
| 4 | `LinkActivity` | `shezdemo://login?token=`, `https://shezguard.example/login?token=` | custom scheme and https without `autoVerify`: another app can receive the token |
| 5 | `ProfileActivity` | extra `profile` (Serializable) | deserialised without checks; `LegacyProfile.readObject` has a side effect (5b) |
| 6 | `ManualCheckActivity` | `https://shezguard.example/manual?name=` | hand-written check for a raw `..`, bypassed by encoding |

Fake data (created by `DemoApp` on every start): `demo.db` with hidden rows `CANARY-HIDDEN-ROW-*`,
`files/secret.txt` with `CANARY-SECRET-7f3a`, and `files/public/readme.txt`.

## Install (emulator)
```sh
./gradlew :app:installVulnerableDebug   # or :app:installProtectedDebug
./gradlew :attacker:installDebug
# or with adb directly (test-only APKs need -t):
adb install -t app/build/outputs/apk/vulnerable/debug/app-vulnerable-debug.apk
```
Then run `scripts/attacks/*.sh` (see `scripts/attacks/README.md`).
