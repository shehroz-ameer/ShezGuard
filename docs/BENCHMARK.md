# Benchmark and footprint (step 14 phase 3)

**Every time in this document was measured on an emulator: emulator, indicative only.** An emulator
runs real ART and framework code, but on virtual CPUs time-shared with the host. Absolute times, and
differences between emulators, do not predict a physical device. Only numbers from the same emulator and
the same method are compared, and the two methods are never mixed in one table. No physical device was
used. The library was not changed for this step.

## Setup (to reproduce)

| | |
|---|---|
| Host | Apple M4, 10 cores, 16 GB, macOS 26.2 |
| Emulator | Android emulator 35.4.9.0, headless (`-no-window -no-snapshot-save`), cold boot, 60 s idle after boot before installing |
| Main AVD | `Pixel_8`: API 34 Google Play image, `sdk_gphone64_arm64`, build `UE1A.230829.036.A4`, patch 2023-09-05, arm64-v8a, 4 vCPUs, 2 GB RAM |
| Second AVD | `Pixel_4`: API 29 Google Play image, build `QSR1.211112.011`, patch 2019-09-05, arm64-v8a, 4 vCPUs, 2 GB RAM |
| Build | `:benchmark` module, instrumented tests only, `testBuildType = "release"`: the test APK is **not debuggable and not minified**, and uses `:shezguard-core`'s release variant. After install the test APK is AOT-compiled with `cmd package compile -m speed -f` (androidx.benchmark refuses to measure otherwise: `NOT-AOT-COMPILED`); both methods measure the same compiled code. |
| Dependencies in the test APK | androidx.benchmark 1.5.0 raises the Kotlin standard library in the test APK to 2.1.21 (Gradle's conflict resolution); the library itself is built against, and ships with, 2.0.21. The measured library code therefore ran with stdlib 2.1.21. |
| API under test | `ShezGuard.evaluate(intent, policy, entryPointName)`, the intent-only overload: no caller lookup (PackageManager) and no domain verification is timed. The policy has no audit sink. |
| Input | Every call gets a **freshly delivered intent**: the scenario's template written to a `Parcel` and read back, with the app's class loader set, as `ActivityThread` delivers it (extras still parcelled). This preparation is outside the timed region in both methods. |
| Exact settings and device properties | `device.txt` in each results folder |

Commands (from the repository root):
```
scripts/bench/run_bench.sh Pixel_8 phase3-bench      # API 34
scripts/bench/run_bench.sh Pixel_4 phase3-bench      # API 29
python3 scripts/bench/summarise.py docs/results/2026-11-17_Pixel_8_api34_phase3-bench
scripts/bench/footprint.sh phase3
```
`run_bench.sh` builds the test APK, boots the AVD (emulator only, the same check as the device tests),
installs and AOT-compiles the APK, runs method A 5 times and method B 3 times (each run a new process via
`am instrument`), pulls the output, uninstalls the APK and shuts the emulator down. It changes no global
device setting. Raw output: `docs/results/2026-11-17_<AVD>_api<N>_phase3-bench/` (`percall_raw.tar.gz`
holds every timed call; `micro_run<k>.json` is androidx.benchmark's own output; `summary.md` is the
output of `summarise.py`).

### Method A: per-call timed loop (median and p95)
`benchmark/src/androidTest/.../PerCallBenchmark.kt`. Per scenario and run: 2 000 untimed warm-up calls,
then **10 000 calls, each timed on its own** with `System.nanoTime()` around the call only. Percentiles are
nearest-rank over the 10 000 calls of one run. **5 runs**, each in a new process; the tables give the range
(min–max) of each statistic over the 5 runs, and the spread of the run medians, (max − min) / min. The ART
GC count is read before and after the timed calls (GCs include those caused by the untimed preparation).
`summarise.py` recomputes everything from the raw samples and checks it against the lines printed on the
device (0 mismatches on both emulators).

### Method B: androidx.benchmark 1.5.0 (Jetpack Microbenchmark)
`MicroBenchmark.kt`, `BenchmarkRule.measureRepeated`, with the intent prepared inside
`runWithMeasurementDisabled`. Used **without** its Gradle plugin (version chosen: 1.5.0, the latest stable;
its AAR metadata requires AGP 8.1.1+ and compileSdk 34+, which AGP 8.10.1 and compileSdk 35 meet). The
library chooses the warm-up and the batch size; it reports 50 measurements, each the **average time per
iteration over a batch**, so its median and minimum are not per-call percentiles and have no p95. Only
the `EMULATOR` error is suppressed. **3 runs**, each in a new process. It also reports allocations per
iteration. On API 34 each run took about 8 minutes (11 scenarios), against about 2 on API 29; not
investigated.

### Scenarios
| Scenario | What | ShezGuard outcome |
|---|---|---|
| `simple_link` | `https://example.com/product/123?id=123&ref=home`: path prefix, 2 declared params | Allow |
| `many_params` | 10 declared + 40 undeclared params under `Unknown.Drop` | Sanitize (`PARAM_UNKNOWN_DROPPED`) |
| `max_length` | 7 params of 256 characters each (the default maximum length); URI about 1 850 characters | Allow |
| `nested_depth1` | one nested intent under `Nested.AllowSanitized` | Sanitize (`NESTED_INTENT_SANITIZED`) |
| `nested_depth4` | nested intents 4 deep (each carrying the next in "next") | Block (`NESTED_INTENT_DENIED`) |
| `large_bundle` | 64 extras: 60 Strings of 256 characters and 4 String arrays of 64 × 32 characters (`maxKeys(64)`) | Allow |
| `early_block_unregistered` | entry point not in the policy: blocked before the intent is read | Block (`ENTRY_POINT_UNKNOWN`) |
| `early_block_scheme` | `http` instead of `https` on the deep-link entry point; ShezGuard still collects every violation | Block (`SCHEME_NOT_ALLOWED`) |
| `baseline_app_reads_link` | no ShezGuard: the app reads `id` and `ref` with `getQueryParameter` | - |
| `baseline_app_reads_bundle` | no ShezGuard: the app reads all 64 extras of the large Bundle | - |
| `baseline_sanitizer_nested1` | no ShezGuard: `IntentSanitizer.sanitizeByFiltering` on the depth-1 nested intent | - |

The outcome was checked on the first warm-up call and the last timed call of every run.

A first trial on API 34 ran without AOT compilation (state `verify`); method B refused to run and the
method A times were higher. That trial was discarded and is not reported.

## Results: API 34 (`Pixel_8`), emulator, indicative only

**Method A, per-call timed loop, µs per call** (5 runs × 10 000 calls; ranges over the 5 runs)

| Scenario | Outcome | Runs × calls | Median, per run (min–max) | p95, per run (min–max) | p99, per run (min–max) | Spread of run medians | GCs during timed calls, per run |
|---|---|---|---|---|---|---|---|
| `simple_link` | ALLOW[] | 5 × 10000 | 12.2–23.6 | 25.2–72.5 | 50.7–232.4 | 93% | 0–0 |
| `many_params` | SANITIZE[PARAM_UNKNOWN_DROPPED] | 5 × 10000 | 147.5–166.0 | 244.9–293.2 | 337.6–409.9 | 12% | 207–226 |
| `max_length` | ALLOW[] | 5 × 10000 | 78.5–152.9 | 122.8–253.0 | 223.6–350.0 | 95% | 138–169 |
| `nested_depth1` | SANITIZE[NESTED_INTENT_SANITIZED] | 5 × 10000 | 2.6–2.9 | 4.1–5.4 | 9.1–14.9 | 11% | 8–8 |
| `nested_depth4` | BLOCK[NESTED_INTENT_DENIED] | 5 × 10000 | 2.7–3.5 | 4.4–8.7 | 8.5–39.0 | 29% | 9–9 |
| `large_bundle` | ALLOW[] | 5 × 10000 | 40.7–51.0 | 149.3–228.0 | 219.9–570.9 | 26% | 105–110 |
| `early_block_unregistered` | BLOCK[ENTRY_POINT_UNKNOWN] | 5 × 10000 | 0.1–0.1 | 0.2–0.5 | 0.6–0.9 | 0% | 1–1 |
| `early_block_scheme` | BLOCK[SCHEME_NOT_ALLOWED] | 5 × 10000 | 10.4–13.2 | 14.7–25.1 | 35.6–70.4 | 27% | 20–22 |
| `baseline_app_reads_link` | - | 5 × 10000 | 0.8–1.0 | 1.4–2.0 | 1.7–6.0 | 25% | 2–2 |
| `baseline_app_reads_bundle` | - | 5 × 10000 | 24.4–27.4 | 31.9–38.5 | 85.5–109.2 | 12% | 69–76 |
| `baseline_sanitizer_nested1` | - | 5 × 10000 | 1.0–1.2 | 1.8–2.0 | 2.2–6.3 | 16% | 4–4 |
Raw files vs device lines: 0 mismatches.

**Method B, androidx.benchmark 1.5.0, µs per iteration** (batch averages, not per-call; ranges over 3 runs)

| Scenario | Runs | Median, per run (min–max) | Minimum, per run (min–max) | Spread of run medians | Allocations per iteration (median) | Measurements × iterations |
|---|---|---|---|---|---|---|
| `simple_link` | 3 | 12.1–14.0 | 11.1–13.6 | 15% | 353 | 50 × 5970 |
| `many_params` | 3 | 161.6–168.5 | 157.4–162.1 | 4% | 3416 | 50 × 467 |
| `max_length` | 3 | 87.5–99.8 | 86.1–95.5 | 14% | 575 | 50 × 1086 |
| `nested_depth1` | 3 | 3.8–3.8 | 3.3–3.4 | 1% | 129 | 50 × 31575 |
| `nested_depth4` | 3 | 3.9–4.1 | 3.5–3.6 | 5% | 112 | 50 × 27586 |
| `large_bundle` | 3 | 60.0–62.1 | 56.9–59.6 | 4% | 875 | 50 × 1776 |
| `early_block_unregistered` | 3 | 0.2–0.2 | 0.1–0.2 | 7% | 9 | 50 × 120048 |
| `early_block_scheme` | 3 | 14.1–14.5 | 11.8–13.7 | 3% | 369 | 50 × 5620 |
| `baseline_app_reads_link` | 3 | 1.0–1.0 | 0.9–0.9 | 2% | 24 | 50 × 61538 |
| `baseline_app_reads_bundle` | 3 | 31.5–32.5 | 28.1–30.7 | 3% | 389 | 50 × 2228 |
| `baseline_sanitizer_nested1` | 3 | 1.6–1.7 | 1.4–1.6 | 11% | 54 | 50 × 63131 |

## Results: API 29 (`Pixel_4`), emulator, indicative only

**Method A, per-call timed loop, µs per call**

| Scenario | Outcome | Runs × calls | Median, per run (min–max) | p95, per run (min–max) | p99, per run (min–max) | Spread of run medians | GCs during timed calls, per run |
|---|---|---|---|---|---|---|---|
| `simple_link` | ALLOW[] | 5 × 10000 | 22.0–24.9 | 36.4–88.7 | 146.1–316.7 | 13% | 17–45 |
| `many_params` | SANITIZE[PARAM_UNKNOWN_DROPPED] | 5 × 10000 | 183.8–304.5 | 321.3–1313.6 | 409.1–3841.5 | 66% | 101–461 |
| `max_length` | ALLOW[] | 5 × 10000 | 92.5–167.1 | 162.1–501.0 | 211.7–1186.9 | 81% | 86–323 |
| `nested_depth1` | SANITIZE[NESTED_INTENT_SANITIZED] | 5 × 10000 | 3.0–6.4 | 4.7–20.2 | 22.5–164.1 | 112% | 2–18 |
| `nested_depth4` | BLOCK[NESTED_INTENT_DENIED] | 5 × 10000 | 3.3–14.5 | 5.2–52.5 | 15.4–248.0 | 334% | 2–18 |
| `large_bundle` | ALLOW[] | 5 × 10000 | 33.0–68.7 | 52.7–233.6 | 120.3–543.0 | 108% | 84–224 |
| `early_block_unregistered` | BLOCK[ENTRY_POINT_UNKNOWN] | 5 × 10000 | 0.2–0.2 | 0.4–1.0 | 0.7–5.4 | 51% | 1–3 |
| `early_block_scheme` | BLOCK[SCHEME_NOT_ALLOWED] | 5 × 10000 | 13.3–26.2 | 19.9–65.5 | 64.8–325.0 | 97% | 13–47 |
| `baseline_app_reads_link` | - | 5 × 10000 | 1.2–2.0 | 1.9–5.1 | 2.5–10.3 | 71% | 1–5 |
| `baseline_app_reads_bundle` | - | 5 × 10000 | 25.6–46.8 | 34.8–152.0 | 80.0–316.2 | 83% | 98–183 |
| `baseline_sanitizer_nested1` | - | 5 × 10000 | 1.4–2.4 | 2.0–4.9 | 3.0–11.1 | 76% | 3–8 |
Raw files vs device lines: 0 mismatches.

**Method B, androidx.benchmark 1.5.0, µs per iteration**

| Scenario | Runs | Median, per run (min–max) | Minimum, per run (min–max) | Spread of run medians | Allocations per iteration (median) | Measurements × iterations |
|---|---|---|---|---|---|---|
| `simple_link` | 3 | 16.4–17.9 | 16.2–17.1 | 9% | 353 | 50 × 5882 |
| `many_params` | 3 | 197.8–325.3 | 193.6–212.1 | 64% | 3422 | 50 × 521 |
| `max_length` | 3 | 127.6–188.3 | 118.2–152.8 | 48% | 575 | 50 × 715 |
| `nested_depth1` | 3 | 4.6–5.0 | 4.3–4.6 | 8% | 125 | 50 × 16108 |
| `nested_depth4` | 3 | 4.8–5.3 | 4.3–4.9 | 12% | 106 | 50 × 11764 |
| `large_bundle` | 3 | 40.0–42.4 | 38.7–40.2 | 6% | 874 | 50 × 1017 |
| `early_block_unregistered` | 3 | 0.2–0.2 | 0.2–0.2 | 2% | 9 | 50 × 100000 |
| `early_block_scheme` | 3 | 17.1–20.0 | 15.3–17.1 | 17% | 369 | 50 × 5309 |
| `baseline_app_reads_link` | 3 | 1.5–1.7 | 1.3–1.5 | 9% | 24 | 50 × 40666 |
| `baseline_app_reads_bundle` | 3 | 31.6–32.5 | 29.3–31.2 | 3% | 389 | 50 × 1235 |
| `baseline_sanitizer_nested1` | 3 | 2.1–2.2 | 1.9–2.0 | 4% | 52 | 50 × 29629 |

## What the numbers do and do not show
- **Spread between runs is large.** On API 34 the run medians of `simple_link` and `max_length` differ by
  about 95 % between the fastest and slowest run, and on API 29 several scenarios exceed 60 % (up to
  334 % for `nested_depth4`). Tails (p95, p99) vary more than medians. Single numbers would be misleading;
  quote ranges. Method B's run medians are steadier (at most 15 % on API 34, up to 64 % on API 29), as
  expected when each measurement averages over a batch.
- **Order of magnitude, API 34, method A:** a simple deep link costs about 12–24 µs per call (median) where
  the app's own reads cost about 1 µs; the worst cases measured are `many_params` (about 148–166 µs) and
  `max_length` (about 80–150 µs). A large Bundle costs about 41–51 µs, against about 24–27 µs for the app
  reading the same extras itself. Nested-intent checks cost about 2.6–3.5 µs, against about 1 µs for
  `IntentSanitizer` alone. These are emulator figures: the ratios are more informative than the absolute
  times, and even ratios may not carry over to a physical device.
- **An early Block is cheap only before the intent is read.** `early_block_unregistered` costs about
  0.1–0.2 µs; `early_block_scheme` still evaluates the whole intent (all violations are collected, a design
  rule), about 10–13 µs on API 34.
- **Allocation drives cost.** Method B counts 353 allocations per call for `simple_link`, 575 for
  `max_length` and 3 416 for `many_params`; method A sees about 20 GCs per 1 000 calls in `many_params`.
- **Not measured:** the Activity overload (caller identity, PackageManager calls, domain verification),
  audit sinks, policy construction, cold start (first call in a process), and a physical device.

## Footprint

Measured by `scripts/bench/footprint.sh phase3`, output in `docs/results/2026-11-17_footprint_phase3/footprint.txt`
(commit and tool versions in its first lines). Sizes do not depend on the emulator.

**Re-run check (2026-11-17, `docs/results/2026-11-17_footprint_phase3-scripts-check/`).** The AAR, the
library dex, every method count, every dex size and every referenced-method count are identical. Each
demo APK is 72 bytes smaller in file size, and 52–103 bytes smaller in download size, than in the first
run. In the rebuilt APKs, `META-INF/version-control-info.textproto` reads
`generate_error_reason: NO_VALID_GIT_FOUND`; the first run's APKs were overwritten, so whether that
entry differed was not checked. The protected-minus-vulnerable difference (40 512 bytes) is unchanged.
The tables below are from the first run.

**The library (release AAR).** 340 757 bytes. Entries: `classes.jar` 314 977 bytes uncompressed
(294 367 compressed), `lint.jar` (the build-time Lint rule, not runtime code) 46 730, `proguard.txt` 1 407,
`AndroidManifest.xml` 200, metadata 156, `R.txt` 0.

**Methods.** `classes.jar` converted to dex with `d8 --release --min-api 24` (build-tools 36.0.0;
android-35 as the library jar; the dex is byte-identical with or without the dependencies on the
classpath): 248 192 bytes, 211 classes, **1 126 methods defined** (apkanalyzer `dex packages
--defined-only`): `policy` 430, `eval` 211, `canon` 79, `android` 70, `audit` 67, `validate` 28, and 241 in
`com.shezguard.core` itself. `method_ids_size` (methods referenced, including the framework, androidx and
Kotlin methods it calls) is 1 379, the figure that counts toward the 64K dex limit.

**R8 on a minified consumer** (the demo app, `:app`; the protected flavor uses ShezGuard, the vulnerable
flavor has it on the classpath but never calls it):

| Build | APK file bytes | Download bytes | Dex bytes | Methods referenced | ShezGuard methods defined |
|---|---|---|---|---|---|
| protected, release (not minified, unsigned) | 4 873 091 | 3 947 975 | 9 450 780 | 63 759 | 1 127 |
| vulnerable, release (not minified, unsigned) | 4 867 431 | 3 939 885 | 9 438 024 | 63 654 | 1 127 |
| protected, minified (R8) | 2 079 350 | 1 180 679 | 1 295 048 | 10 541 | **356** (125 classes) |
| vulnerable, minified (R8) | 2 038 838 | 1 137 587 | 1 212 384 | 10 092 | 2 (the kept `@GuardedEntryPoint`) |

- R8 keeps 356 of the 1 126 library methods in the protected demo (counted with apkanalyzer using R8's
  `mapping.txt`, which attributes renamed code to its original package). Which of the removed methods
  this demo's policy simply never reaches was not analysed.
- With R8, the protected APK is **40 512 bytes larger** than the vulnerable one (download size 43 092
  bytes, dex 82 664 bytes, 449 more methods referenced). This difference is everything the protected flavor
  adds: ShezGuard, the demo's policy and `EntryGuard` code, and the androidx and Kotlin code they pull in
  (`IntentSanitizer` among it). It is an upper bound for ShezGuard in this app, not ShezGuard alone.
- In the vulnerable flavor R8 removes the library except `@GuardedEntryPoint`, which the library's consumer
  rules keep (`-keep @interface`).
- Without R8 the whole library ships (1 127 methods; one more than the standalone d8 count above; the
  difference was not investigated).

**Runtime dependencies** (`releaseRuntimeClasspath`): `androidx.core:core:1.9.0` and its own dependencies
(annotation, annotation-experimental, collection, concurrent-futures, listenablefuture, lifecycle-runtime,
core-runtime, versionedparcelable) and the Kotlin standard library 2.0.21. Unchanged by this step.

## Optimisation candidates for step 16 (not applied)
Suggested by the measurements; none was investigated in the code or applied.
1. **Parameter handling allocates heavily:** 3 416 allocations per call with 50 parameters, 353 with 2.
   Find where per-parameter allocation happens (canonicalisation, decoding, violation lists) and reduce it.
2. **Long values cost per character:** `max_length` (about 1 850 characters) costs several times
   `simple_link`. Check whether the URI or each value is scanned or copied more than once.
3. **Extras are unparcelled twice when the app reads them after an Allow.** ShezGuard unparcels its own
   copy (N5), and `Decision.Allow.intent` is the original intent, so an app reading extras pays again
   (`large_bundle` about 41–51 µs plus `baseline_app_reads_bundle` about 24–27 µs on API 34). Option:
   give the app the checked copy. This changes the API contract, so it is a design decision, not a tweak.
4. **Not a candidate:** making `early_block_scheme` stop at the first hard violation would break the
   "collect all violations" rule.
