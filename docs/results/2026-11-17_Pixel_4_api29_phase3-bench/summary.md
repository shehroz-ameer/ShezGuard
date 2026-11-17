Source: `2026-11-17_Pixel_4_api29_phase3-bench`

Method A, per-call timed loop (µs per call; emulator, indicative only)

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

Method B, androidx.benchmark 1.5.0 (µs per iteration, batch averages; emulator, indicative only)

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

