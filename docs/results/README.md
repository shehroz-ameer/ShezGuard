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
- `scripts/device/run_shared_tests.sh <AVD>`: boot, check, set and restore the hidden-API setting, run
  `connectedDebugAndroidTest`, collect logcat and XML into this folder.
- `scripts/device/extract_tagged.py`: the tagged lines (`[103]`, `[111]`, `[117]`, `[N6]`, `[N7s]`,
  `[N7d]`, `[N8]`, `[baseline]`) from JUnit XML or logcat (`System.out` only).
- `scripts/device/compare_with_robolectric.py <robolectric dir> <logcat> <api>`: compares one run with
  Robolectric; exit 1 on any difference at the same SDK or any differing count.
- `scripts/device/check_hidden_api_policy.sh <AVD> [--reset]`: reads (and optionally resets and
  re-checks) the setting across cold boots.
