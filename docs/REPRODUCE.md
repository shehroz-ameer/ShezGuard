# Reproducing the results

Exact commands to rerun every test, check and measurement in this repository, with the counts and labels expected at
version 0.1.0 (2026-11-18). Nothing here needs secrets, keys or network access beyond the first Gradle dependency
download. All commands run from the repository root.

**Environment used:** macOS (arm64), JDK 17 (OpenJDK 17.0.19), Gradle 8.11.1 (wrapper), AGP 8.10.1, Kotlin 2.0.21,
Android SDK platforms 34–36, build-tools 36.0.0, Robolectric 4.14.1. Python 3.9+ (standard library only) for the scripts.

**Labels.** JVM results are **Robolectric-only** or **JVM**; emulator results are **confirmed (emulator, API N)** and
timings are **emulator, indicative only** (`docs/PAPER_NOTES.md`). No physical device was used.

## 1. JVM test suites

```sh
./gradlew :shezguard-core:test        # 907 tests per variant (testDebugUnitTest, testReleaseUnitTest), 0 failures
./gradlew :shezguard-lint:test        # 44 lint-tests
./gradlew :app:test                   # demo app: 7 (protected) + 1 (vulnerable) per build type
```

- Every `Test` task has a 20-minute timeout. **Standing rule:** no test that overflows the stack runs under Robolectric
  (`docs/HARDENING.md`); the overflow tests are device-only (section 5).
- The step 15 baseline was 896 per variant; the 11 additional names are listed in `CHANGELOG.md`.

## 2. Hardening suites (not part of `test` or `check`)

```sh
./gradlew :shezguard-core:hardeningTest   # 36 tests, 0 failures (one JVM per test class)
./gradlew :shezguard-lint:hardeningTest   # 5 tests, 0 failures
```

Reports: `shezguard-core/build/hardening/` (`fuzz.txt`, `sink-fuzz.txt`, `resource.txt`). Timings there are **JVM
only**.

### Fuzz seeds

| Test | Seed(s) | Inputs | Expected |
|---|---|---|---|
| `DifferentialFuzzHardeningTest` | `0x5EED0015` | 40 000 | only the documented categories (L11 `+`, host case); `GETPATH_DUPLICATE_SLASH` gone since H2 |
| `SinkOracleFuzzHardeningTest` | `0x514B0001`, `0x514B0002` | 400 000 each (× 2 entry points) | no H2-like, H3-like or new case; only "H3-boundary" (L47, documented) |
| `EvaluateInvariantsTest.evaluateNeverThrowsOnFuzzedIntents` (normal suite) | fixed in the test | 4 000 | no `EVALUATION_FAILED` |

Run one alone with `--tests '*SinkOracleFuzz*'` (JVM, a few seconds per seed).

## 3. Mutation checks (JVM)

```sh
python3 scripts/mutation/run_mutants.py scripts/mutation/<script>.py
```

| Script | Mutants | Expected |
|---|---|---|
| `step10_activity_guard.py` | a1–f | all caught (`docs/MUTATION_CHECKS.md`) |
| `step13_coverage.py`, `step13_guard_calls.py`, `step13_deep_link.py` | Lint rule | all caught |
| `step14_shared_wiring.py` | w1 | caught |
| `step16_h2_get_path.py` | h2 | caught |
| `step16_h3_matrix_dot.py` | h3 | caught |
| `step16_h6_policy_copies.py`, `step16_h6_dsl_copies.py` | h6a, h6b, h6c | caught |
| `step16_h8_uri_bound.py`, `step16_h8_param_cap.py` | h8, h8b | caught |
| `step16_h1_stack_overflow.py` | h1a–h1c | **device-only, by hand** (the runner is JVM-only): see `docs/MUTATION_CHECKS.md` for the procedure; each caught on API 34 or API 24 |

The runner restores the target file byte for byte and prints its SHA-256.

## 4. Emulator images

All arm64-v8a: `ShezGuard_API_24` (google_apis, Android 7.0), `Pixel_4` (API 29, Play), `ShezGuard_API_33` (google_apis),
`Pixel_8` (API 34, Play), `Medium_Phone_API_36` (Play). Exact fingerprints and patch levels are in each results folder's
`device.txt`. The scripts refuse to run on anything that is not an emulator.

## 5. Instrumented tests on an emulator

```sh
scripts/device/run_shared_tests.sh <AVD> <run label>     # e.g. Pixel_8 phase6-fixes
```

- Boots the AVD cold, runs `:shezguard-core:connectedDebugAndroidTest` (src/sharedTest + src/androidTest), and writes
  `docs/results/<date>_<AVD>_api<N>_<label>/` with `device.txt`, `tagged.txt` and `results.txt`. It never keeps raw
  logcat, scrubs the folder and fails if anything remains, and refuses an existing folder.
- Sets `hidden_api_policy 1` on API 28+ for the duration and restores it afterwards.
- Expected at 0.1.0: **94 tests, 0 failures** (API 34: 4 skipped; API 24: 3 skipped), as in
  `docs/results/2026-11-18_*_phase6-fixes/`.
- **Cold-process H1 check** (each `DeepNesting*DeviceTest` class in its own `am instrument` process): install the test
  APK with `ANDROID_SERIAL=<serial> ./gradlew :shezguard-core:installDebugAndroidTest`, then for each class
  `adb shell am instrument -w -r -e class com.shezguard.core.device.<Class> com.shezguard.core.test/androidx.test.runner.AndroidJUnitRunner`.
  Expected lines: `docs/results/2026-11-18_*_phase6-cold-process/`.

## 6. Benchmark (emulator, indicative only)

```sh
scripts/bench/run_bench.sh <AVD> <run label>                     # full: method A (5 × 10 000 calls) + method B
MICRO_RUNS=0 scripts/bench/run_bench.sh Pixel_8 <label>          # per-call loop only
BENCH_SCENARIOS=h8_cap_worst,simple_link BENCH_WARMUP=3 BENCH_SAMPLES=30 PERCALL_RUNS=3 MICRO_RUNS=0 \
  scripts/bench/run_bench.sh Pixel_8 <label>                     # slow scenarios with few samples
python3 -I scripts/bench/summarise.py docs/results/<folder>      # Markdown table
```

Reference figures (API 34, per-call median per run): `simple_link` 12.2–23.6 µs (phase 3), 15.1–19.2 µs (after the
step 16 fixes); `many_params` 147.5–166.0 µs (phase 3), 133.7–146.2 µs (after); `h8_cap_worst` 5.20 s before the parameter
cap, 483–494 µs after (`docs/LIMITATIONS.md` L46). Expect wide run-to-run spread on emulators (`docs/BENCHMARK.md`).

## 7. Footprint

```sh
scripts/bench/footprint.sh <run label>     # docs/results/<date>_footprint_<label>/footprint.txt
```

Measures the release AAR, method counts (d8, apkanalyzer, dexdump), R8 on the demo app and the runtime dependencies
(`docs/BENCHMARK.md`, "Footprint").

## 8. Demo attack scripts

```sh
scripts/attacks/run_all.sh       # see scripts/attacks/README.md; results in docs/ATTACK_MATRIX.md
scripts/attacks/run_benign.sh
```

## 9. Packaging (step 17)

```sh
./gradlew publishToMavenLocal
```

Expected in `~/.m2/repository/io/github/shehroz-ameer/`: `shezguard-core/0.1.0/` (`.aar` containing `classes.jar`,
`lint.jar`, `proguard.txt`; `-sources.jar`; `.pom` and `.module` listing only `androidx.core:core:1.9.0` and
`kotlin-stdlib:2.0.21`) and `shezguard-lint/0.1.0/` (`.jar`, `-sources.jar`, `.pom`).

**Consumer check** (step 17; a throw-away project outside the repository, not committed): an Android app with
`mavenLocal { content { includeGroup("io.github.shehroz-ameer") } }`, AGP 8.10.1, Kotlin 2.0.21, compileSdk 34,
`implementation("io.github.shehroz-ameer:shezguard-core:0.1.0")`, one `@GuardedEntryPoint("product")` activity using
`ActivityGuard`, one exported unannotated activity, and a `minified` build type
(`initWith(debug)`, `isMinifyEnabled = true`, `proguard-android-optimize.txt`). Expected:

- `./gradlew :app:testDebugUnitTest`: 2 Robolectric tests pass;
- `./gradlew :app:lintDebug`: one `ShezGuardUnguardedEntryPoint` on the unannotated activity;
- the `minified` APK on an API 34 emulator, `adb shell am start -a android.intent.action.VIEW -d '<link>' -n <pkg>/.GuardedActivity`:
  `https://example.com/product/42?id=42` is allowed; `…/product/../admin?id=42` and `…?id=42&x=1` are blocked.
