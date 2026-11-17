"""Step 14 wiring check: a mutant caught by a test class that now lives in src/sharedTest.

No earlier recorded mutant is caught by a moved class (steps 1-7 recorded none; steps 8-13 target
ActivityGuardTest, CallerAndroidTest, the audit tests and the Lint rule), so this is a new mutant of a
step 6 behaviour (docs/PAPER_NOTES.md N9 point 3): a nested intent that IntentSanitizer leaves inside
its own output must be denied. Run on the JVM (Robolectric), like every mutant.
"""

FILE = "shezguard-core/src/main/java/com/shezguard/core/android/AndroidExtras.kt"
TESTS = ["com.shezguard.core.eval.NestedIntentTest"]

MUTANTS = [
    {
        "id": "w1",
        "description": "a nested intent left inside IntentSanitizer's output is not denied",
        "edits": [("                leavesNestedIntent(output) -> NestedResult.Denied\n", "")],
    },
]
