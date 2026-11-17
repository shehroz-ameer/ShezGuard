Source: `2026-11-17_Pixel_8_api34_phase3-bench`

Method A, per-call timed loop (µs per call; emulator, indicative only)

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

Method B, androidx.benchmark 1.5.0 (µs per iteration, batch averages; emulator, indicative only)

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

