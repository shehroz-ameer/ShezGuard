# Mutation checks

Hand-written mutants that check whether a test suite would notice a specific, plausible bug. These
are deliberate, targeted mutations of security-relevant lines, not a mutation-testing framework,
and they make no coverage claim. Results per step are recorded in `docs/MUTATION_CHECKS.md`.

## Run

From anywhere inside the repository (Python 3.9+, standard library only):

```sh
python3 scripts/mutation/run_mutants.py scripts/mutation/step10_activity_guard.py
python3 scripts/mutation/run_mutants.py scripts/mutation/step10_activity_guard.py --only a1,e
python3 scripts/mutation/run_mutants.py scripts/mutation/step10_activity_guard.py --variant Release
```

What it does:
1. Copies the target file to `shezguard-core/build/mutation/<name>.orig` and records its SHA-256.
2. Runs the selected tests unmutated (baseline). It refuses to continue unless every test passes,
   so a test that already fails can never count as catching a mutant.
3. For each mutant: applies its edits, runs the selected tests (`--tests <Class>*`, so that
   Robolectric's per-SDK cases such as `name[24]` are included), records the failing tests, and
   restores the original bytes in a `finally` block.
4. Verifies the restored file's SHA-256 and prints a Markdown table.

Verdicts: **caught** (at least one selected test failed), **SURVIVED** (the tests ran and all
passed), **BUILD ERROR** (no test ran, for example because the mutant did not compile; never
counted as caught).

If the run is killed hard (for example `kill -9`), restore the target from the `.orig` backup
before doing anything else, and check it with `git diff` or the printed SHA-256.

## Defining mutants

One Python file per step, with three names:

```python
FILE = "shezguard-core/src/main/java/com/shezguard/core/ActivityGuard.kt"
TESTS = ["com.shezguard.core.activity.ActivityGuardTest"]
MUTANTS = [
    {
        "id": "e",
        "description": "a blocked onCreate does not set RESULT_CANCELED",
        "edits": [("                activity.setResult(Activity.RESULT_CANCELED, null)\n", "")],
    },
]
```

Each edit is an exact `(old, new)` text pair. `old` must occur exactly once in the file at that
point, otherwise the runner stops before changing anything; include enough surrounding lines to
make it unique. Mutants of one file are applied to a fresh copy of the original, never on top of
each other.

## Limits

- One target file per definitions file.
- The tests selected in `TESTS` are the only ones run. A mutant that survives them might be caught
  elsewhere in the suite; say so if you rely on that.
- Each mutant costs one Gradle test run (about 20–30 s here).
