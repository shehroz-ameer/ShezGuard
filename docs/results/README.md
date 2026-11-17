# Step 14 results: emulator runs of the shared tests

Raw evidence for the device checks of step 14. Wording rule: a result here is **confirmed (emulator,
API N)**. An emulator runs real Android framework code (ART, native `Parcel`, `system_server`), but it
is not a physical device and does not cover OEM changes. No physical device was used.

## Folders
| Folder | What |
|---|---|
| `2026-11-17_robolectric_jvm/` | Robolectric reference: JUnit XML of the six `src/sharedTest` classes (`testDebugUnitTest`), their tagged lines (`tagged.txt`), and the full JVM test-name lists (896 per variant) |
| `2026-11-17_<AVD>_api<N>/` | One emulator run: `device.txt` (build, patch, ABI, `hidden_api_policy` before / during / after, commit), JUnit XML, full `logcat.txt`, `tagged.txt`, `gradle.txt` |

Emulators (all arm64-v8a): `ShezGuard_API_24` (google_apis, Android 7.0, patch 2017-10-05),
`Pixel_4` (API 29, Play image), `ShezGuard_API_33` (google_apis, patch 2024-03-01), `Pixel_8` (API 34,
Play image, patch 2023-09-05), `Medium_Phone_API_36` (Play image, patch 2025-04-05). Exact fingerprints
are in each `device.txt`.

## How the tests run on both
- `shezguard-core/src/sharedTest/java` is a source directory of both `test` (JVM) and `androidTest`
  (instrumented). Its classes use `@RunWith(AndroidJUnit4::class)`: on the JVM that runner delegates to
  Robolectric and keeps each class's `@Config(sdk = ...)`; on an emulator it runs once, at the
  emulator's API level. Moved there: `UriCanonicalizerDifferentialTest`, `ExtrasUnparcelTest`,
  `SerializableExtrasTest`, `NestedIntentTest`, `IntentCopyParcelTest`, `IntentSanitizerBaselineTest`,
  and the fixtures `EvalFixtures`, `ExtrasFixtures`, `SerialFixtures`.
- Device-only classes in `src/androidTest`: `NestedIntentClassLoaderTest` (N8) and
  `ExtrasClassLoaderTest` (extras with and without the app's class loader).
- The instrumented test APK targets SDK 35 (`testOptions.targetSdk`); the library declares no
  targetSdk.
- `ExtrasFixtures.received()` gives the received intent the app's class loader, as
  `ActivityThread.performLaunchActivity` and `deliverNewIntents` do. Before this (phase 1), the shared
  extras tests passed on emulators **without reaching the hostile code**: with no loader, the
  framework resolves app classes with the boot class loader (N8), so the hostile `CREATOR` was never
  found ("ran 0x"). The tests now assert that the hostile `CREATOR` ran, and print `[N7s] ... ran Nx`.
  `compare_with_robolectric.py` fails on any count that differs from Robolectric.
- Phase 2 moved `CraftedUriParcelTest` (N4) to `src/sharedTest`, skipped above API 29 by an assumption
  (on the JVM it runs at SDK 29 as before; the JVM count stays 896 per variant, same names). Its
  Robolectric XML was added to `2026-11-17_robolectric_jvm/`.

## Phase 2: caller identity, package visibility, domain verification, crafted `Uri`
Device-only classes in `src/androidTest` (emulator only, run by the same script):
- `CallerIdentityDeviceTest`: `:attacker`'s `IdentityActivity` launches probe activities of the test
  APK (`device/probe/Probes.kt`, declared in `src/androidTest/AndroidManifest.xml`). Before each test the
  attacker is uninstalled and reinstalled from `/data/local/tmp/shezguard-attacker.apk`, so no
  visibility grant carries over. The test APK starts the attacker only through the shell (`am start`),
  never resolving it itself. Its merged manifest has no `<queries>` of its own; androidx.test adds
  `<queries>` for `androidx.test.orchestrator`, `androidx.test.services` and
  `com.google.android.apps.common.testing.services` only.
- `DomainVerificationDeviceTest`: `autoVerify` filters for `dv-verified.invalid`, `dv-selected.invalid`,
  `dv-unverified.invalid`. **States set with `pm set-app-links` / `pm set-app-links-user-selection` /
  `pm set-app-links-allowed`, not by real Digital Asset Links verification**; reset in `@After`. The
  `Signatures:` line of `pm get-app-links` is dropped before printing.
- `CraftedUriDeviceTest`: N4 in process at the emulator's level, and cross process (`:attacker` builds the
  `Uri` with its own `Uri.CREATOR` and sends it through `system_server`).
- The caller tests' parcelled-extras checks use the same reflection as N5/N6, so they also rely on the
  hidden-API setting on API 28+.
- Signing: the policy lists the attacker with the SHA-256 of the test APK's own certificate, read from
  the installed package at run time (both are debug builds from this machine; no keystore is read, and
  the digest is never printed). The for-result test would fail if they differed.

Results, 2026-11-17 (84 instrumented tests per level, 0 failed; skips are level guards):

| | API 24 | API 29 | API 33 | API 34 | API 36 |
|---|---|---|---|---|---|
| Fresh attacker visible to the test APK (no `<queries>`) | yes | yes | **no** | **no** | **no** |
| Plain launch: calling / launchedFrom / referrer | null / - / attacker | null / - / attacker | null / - / **null** | null / null / **null** | null / null / **null** |
| Plain launch: "partner" (attacker allowed, advisory) | `CALLER_UNIDENTIFIED` (`REFERRER_SYSTEM`) | same | `CALLER_UNIDENTIFIED` (`NONE`) | same | same |
| For result: calling, visible after, "partner" / "wrongKey" | attacker, yes, Allow (`CALLING_PACKAGE`) / `CALLER_NOT_ALLOWED_RELIABLE` | same | same | same | same |
| Shared identity: launchedFrom, visible after, "partner" | - | - | - | attacker, yes, Allow (`LAUNCHED_FROM_PACKAGE`) | same |
| Forward result: calling / launchedFrom, "partner" | attacker / -, Allow | same | same | attacker / **test APK**, Block (`CALLER_NOT_ALLOWED_RELIABLE`, L43) | same |
| Spoofed `EXTRA_REFERRER` / `_NAME`: `getReferrer()`, "router" | demo app, `CALLER_UNIDENTIFIED` (`REFERRER_EXTRA`) | same | same | same | same |
| Extras, no referrer: ShezGuard leaves both Bundles parcelled; `getReferrer()` unparcels | yes; yes | yes; yes | yes; yes | yes; yes | yes; yes |
| `onNewIntent` (attacker and shell): calling (and launchedFrom on 34+) still the launch's caller; ShezGuard `NONE`, `CALLER_UNIDENTIFIED`; same intent evaluated as LAUNCH would be allowed | yes | yes | yes | yes | yes |
| Domain: approved / user-selected / none / undeclared; approved with link handling off | all `UNAVAILABLE` | all `UNAVAILABLE` | pass / `NOT_VERIFIED` x3; `NOT_VERIFIED` | same | same |
| N4 bytes in process | accepted, forms disagree | same | rejected (`IllegalArgumentException: Unknown representation: 115`) | accepted as `Uri` "h", forms agree | same as 34 |
| N4 cross process | **survives delivery**; ShezGuard Block `URI_PARSER_MISMATCH` | same | attacker cannot build it; nothing sent | "h" delivered; Block `URI_MALFORMED` | same as 34 |

"same" = same as the cell to the left. Full lines: `[N4d]`, `[N11d]`, `[N12d]`, `[N13d]` in each run's
`tagged.txt`. `:attacker` was put back as found on each AVD (`attacker_installed_before/after` in
`device.txt`); AGP uninstalls the test APK after the run (`test_apk_installed_after=0`), which also
removes the domain states set via pm.

## Test-only dependencies added in step 14
| Catalog entry | Coordinates | Configuration | Why |
|---|---|---|---|
| `androidx-junit` (existing) | `androidx.test.ext:junit:1.2.1` | `testImplementation` (was only `androidTestImplementation`) | `AndroidJUnit4` runner for `src/sharedTest` on the JVM |
| `robolectric-annotations` (new) | `org.robolectric:annotations:4.14.1` (same version as `robolectric`, `version.ref = "robolectric"`) | `androidTestCompileOnly` | `@Config(sdk = ...)` on shared classes must compile for `androidTest`; ART ignores the annotation at run time because its class is absent |

Checked 2026-11-17 with `./gradlew :shezguard-core:dependencies --configuration <c>`: `org.robolectric`
appears in `debugAndroidTestCompileClasspath` only (1 entry, `annotations:4.14.1`), and in none of
`releaseRuntimeClasspath`, `releaseCompileClasspath`, `debugRuntimeClasspath`, `debugCompileClasspath`,
`debugAndroidTestRuntimeClasspath`. `releaseRuntimeClasspath` is still `androidx.core:core:1.9.0` and
the Kotlin stdlib. **No publication is configured** (no `maven-publish` plugin, no `publishing {}`
block), so there is no POM or Gradle module metadata to check; the release AAR contains `R.txt`,
`AndroidManifest.xml`, `classes.jar`, `proguard.txt`, `lint.jar` and `aar-metadata.properties`, none
of which lists dependencies.

## Hidden-API setting
`scripts/device/run_shared_tests.sh` sets `settings put global hidden_api_policy 1` on API 28+
emulators for the run, so the reflection in `ExtrasFixtures.extrasParcelled` and `IntentCopyParcelTest`
(`Intent.mExtras`, `BaseBundle.isParcelled()`, N5/N6 checks) is allowed. **Every API 29, 33, 34 and 36
result here used it.** API 24 has no hidden-API enforcement; the setting is not touched there. The
script refuses to run unless the serial is `emulator-*` and `ro.kernel.qemu` or `ro.boot.qemu` is 1.

**Restore bug found and fixed (2026-11-17).** The phase 1 runs restored the value (`settings delete`)
and read back `null`, but then killed the emulator with `adb emu kill` before SettingsProvider wrote the
change to disk. The AVDs for API 29, 33, 34 and 36 then booted with `hidden_api_policy=1`, and the first
follow-up runs recorded `before=1`. Fix: after restoring, wait 5 s, `sync`, and shut down with
`reboot -p`. `scripts/device/check_hidden_api_policy.sh <AVD> --reset` put each AVD back to unset
(`null`, the value phase 1 found on all of them) and proved it with a second cold boot. The `device.txt`
of each final run records `hidden_api_policy_before`, `_during_run` and `_after_restore`, and a cold boot
after each final run read `null` again.

## Scripts
- `scripts/device/run_shared_tests.sh <AVD>`: build and push `:attacker`, boot, check, set and restore
  the hidden-API setting, run `connectedDebugAndroidTest`, collect logcat and XML into this folder, put
  `:attacker` back as found.
- `scripts/device/extract_tagged.py`: the tagged lines (`[103]`, `[111]`, `[117]`, `[N4]`, `[N4d]`,
  `[N6]`, `[N7s]`, `[N7d]`, `[N8]`, `[N11d]`, `[N12d]`, `[N13d]`, `[baseline]`) from JUnit XML or logcat (`System.out` only).
- `scripts/device/compare_with_robolectric.py <robolectric dir> <logcat> <api>`: compares one run with
  Robolectric; exit 1 on any difference at the same SDK or any differing count.
- `scripts/device/check_hidden_api_policy.sh <AVD> [--reset]`: reads (and optionally resets and
  re-checks) the setting across cold boots.
