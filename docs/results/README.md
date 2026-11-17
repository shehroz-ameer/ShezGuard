# Step 14 results: emulator runs of the shared tests

Raw evidence for the device checks of step 14. Wording rule: a result here is **confirmed (emulator,
API N)**. An emulator runs real Android framework code (ART, native `Parcel`, `system_server`), but it
is not a physical device and does not cover OEM changes. No physical device was used.

## Folders
| Folder | What |
|---|---|
| `2026-11-17_robolectric_jvm/` | Robolectric reference: JUnit XML of the six `src/sharedTest` classes (`testDebugUnitTest`), their tagged lines (`tagged.txt`), and the full JVM test-name lists (896 per variant) |
| `2026-11-17_<AVD>_api<N>_<label>/` | One emulator run: `device.txt` (run label, build, patch, ABI, `hidden_api_policy` before / during / after, attacker and test APK state, commit), `tagged.txt`; runs before the secret-scan follow-up also keep their JUnit XML and `gradle.txt`, later runs keep `results.txt` (one line per test) instead. **No raw logcat** (see below) |

**Run labels.** Every run folder ends in a label naming the phase, and `run_shared_tests.sh` refuses to
write into an existing folder, so a later run never overwrites an earlier one. Phase 2 had overwritten
the phase 1 folders (same date and name); they were renamed afterwards: `_phase1` folders are restored
unchanged from commit 6c63345 (phase 1 and its follow-ups, 67 tests per level), `_phase2` folders
are the phase 2 runs from commit 8c80605 (84 tests per level), and `_phase2-followup` folders (API 34 and
36 only) add the plain internal launch test for L43 (85 tests). The Robolectric folder
`2026-11-17_robolectric_jvm/` is a reference, updated only by adding files (phase 2 added
`CraftedUriParcelTest`).

Phase 3 (benchmark and footprint, `docs/BENCHMARK.md`): `2026-11-17_Pixel_8_api34_phase3-bench/` and
`2026-11-17_Pixel_4_api29_phase3-bench/` (written by `scripts/bench/run_bench.sh`: `device.txt`,
`percall_lines.txt`, `percall_raw.tar.gz`, `micro_run<k>.json`, instrumentation output, `summary.md` from
`scripts/bench/summarise.py`), and `2026-11-17_footprint_phase3/footprint.txt`
(`scripts/bench/footprint.sh`). Both scripts also refuse to overwrite an existing folder.

Script checks (not results): `2026-11-17_Pixel_8_api34_phase3-scripts-check/` (`run_shared_tests.sh`
with `SCRUB_SELFTEST=1`; the tests themselves ran normally), `2026-11-17_Pixel_8_api34_phase3-scripts-check-bench/`
(`run_bench.sh` with `BENCH_SCRIPT_CHECK=1` and `SCRUB_SELFTEST=1`: 1 process, 200 timed calls, dry-run
microbenchmark; its numbers are marked NOT RESULTS and are not used anywhere), and
`2026-11-17_footprint_phase3-scripts-check/` (a footprint re-run; differences in `docs/BENCHMARK.md`).
`_phase4-followup/`: all five emulators after the N8 class-loader test was added.

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

## Instrumented test counts per emulator

| Run | API 24 | API 29 | API 33 | API 34 | API 36 |
|---|---|---|---|---|---|
| `_phase1` (phase 1 and its follow-ups) | 67, 0 skipped | 67, 0 skipped | 67, 1 skipped | 67, 1 skipped | 67, 1 skipped |
| `_phase2` | 84, 3 skipped | 84, 3 skipped | 84, 5 skipped | 84, 4 skipped | 84, 4 skipped |
| `_phase2-followup` (+ plain internal launch, L43) | not run | not run | not run | 85, 4 skipped | 85, 4 skipped |
| `_phase3-scripts-check` (script check, same tests) | – | – | – | 85, 4 skipped | – |
| `_phase4-followup` (+ extras class loader, N8) | 86, 3 skipped | 86, 3 skipped | 86, 5 skipped | 86, 4 skipped | 86, 4 skipped |

0 failures in every run. In `_phase1`, the 1 skip on API 33, 34 and 36 is
`characterisesPartialMapAfterFailedUnparcel`. Skips in later runs are listed below; the two tests added
after phase 2 skip on no level.

## Skipped tests per level (phase 2 and follow-up runs)
Every skip is a JUnit assumption on the API level; none hides a failure. Phase 2 runs: 84 tests per level;
follow-up runs (API 34, 36): 85.

| Test | Skipped on | Reason (assumption) |
|---|---|---|
| `CallerIdentityDeviceTest.sharedIdentityIsReliableOnApi34` | 24, 29, 33 | `ActivityOptions.setShareIdentityEnabled` exists from API 34 |
| `DomainVerificationDeviceTest.mapsThePlatformDomainStates` | 24, 29 | `DomainVerificationManager` exists from API 31 |
| `DomainVerificationDeviceTest.linkHandlingDisallowedMeansNotVerified` | 24, 29 | same |
| `DomainVerificationDeviceTest.domainVerificationIsUnavailableBelowApi31` | 33, 34, 36 | checks the below-31 path only |
| `CraftedUriParcelTest.blocksCraftedParcelWhoseDecodedPathDisagreesWithEncoded` | 33, 34, 36 | representation `BOTH` is read only up to API 29 (N4); 30+ is covered by `CraftedUriDeviceTest` |
| `CraftedUriParcelTest.consistentCraftedParcelIsAllowed` | 33, 34, 36 | same |
| `ExtrasUnparcelTest.characterisesPartialMapAfterFailedUnparcel` | 33, 34, 36 | from API 33 the hostile value is lazy and `keySet()` succeeds (N7), so there is no partial map to characterise |

Totals: API 24 and 29: 3 skipped; API 33: 5; API 34 and 36: 4. On the JVM the 2 skips per variant are
`ExtrasUnparcelTest.characterisesPartialMapAfterFailedUnparcel` at SDK 34 (same reason) and
`CallerAndroidTest.rotatedOutSigningKeyIsNotAccepted` at SDK 24 (signing lineage exists from API 28).

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
  the hidden-API setting, run `connectedDebugAndroidTest`, write `device.txt`, `tagged.txt` and
  `results.txt` into this folder (raw logcat, XML and Gradle output stay in a temporary folder), put
  `:attacker` back as found, scrub the folder and fail if a pattern remains.
- `scripts/device/junit_summary.py <xml dir>`: one line per test (PASS / SKIP / FAIL with the first line
  of the message).
- `scripts/device/scrub.py <folder> [--check] [--literals FILE]`: masks secrets and identifiers, then
  re-scans; exit 1 if anything remains (see "Raw logs and secrets").
- `scripts/device/extract_tagged.py`: the tagged lines (`[103]`, `[111]`, `[117]`, `[N4]`, `[N4d]`,
  `[N6]`, `[N7s]`, `[N7d]`, `[N8]`, `[N11d]`, `[N12d]`, `[N13d]`, `[baseline]`) from JUnit XML, a logcat dump (`System.out` only) or a `tagged.txt`.
- `scripts/device/compare_with_robolectric.py <robolectric dir> <tagged.txt> <api>`: compares one run with
  Robolectric; exit 1 on any difference at the same SDK or any differing count.
- `scripts/device/check_hidden_api_policy.sh <AVD> [--reset]`: reads (and optionally resets and
  re-checks) the setting across cold boots.

## Raw logs and secrets (follow-up of 2026-11-17)
A secret scan flagged a Google API key in the phase 2 API 29 raw logcat. It was logged by the Play Store
(`com.android.vending`, tag `Firebase-Installations`), part of the emulator's Google Play system image,
not by this project. Raw logcat also carried the host's adb public key and `user@host` name (logged by
the emulator's `AdbDebuggingManager`, phase 1, API 29). So:
- **Every raw `logcat.txt` was removed** from `docs/results` (all `_phase1`, `_phase2` and
  `_phase2-followup` folders; the phase 3 folders never had one). The tagged lines kept in `tagged.txt`
  are exactly what `extract_tagged.py` extracts from those logcats, and
  `compare_with_robolectric.py` gives identical output (exit 0) from `tagged.txt` for all 12 runs; this
  was checked before the logcats were removed.
- The run scripts now keep **only filtered output** in `docs/results`: `device.txt`, `tagged.txt`,
  `results.txt` (device tests); `percall_lines.txt` (filtered `[BENCH-PERCALL]` lines),
  `percall_raw.tar.gz` (numbers only), `micro_run<k>.json` (androidx.benchmark's results and device
  context) and `instrument_status.txt` (benchmark); `footprint.txt`. Raw logcat, JUnit XML and full
  instrumentation output go to a temporary folder that is deleted.
- **Scrub step** (`scripts/device/scrub.py`), run by `run_shared_tests.sh`, `run_bench.sh` and
  `footprint.sh` before they finish: masks Google API keys (`AIza…`), OAuth tokens (`ya29.`), AWS key
  ids (`AKIA…`), private-key PEM headers, email addresses (except the test-fixture domains listed in the
  script, e.g. `evil.com`, `example.com`, `uri.path`), device serial numbers (`ro.serialno`,
  `ro.boot.serialno`, read from the device, and the `EMULATOR…X…` form), the host's adb public key, and
  certificate fingerprints (colon hex, and the debug certificate's SHA-256 and SHA-1 digests read from the
  built APK's public certificate). It re-scans afterwards and the run fails if anything remains.
- The git history was rewritten on 2026-11-17 to remove the raw logcat files from every commit.

