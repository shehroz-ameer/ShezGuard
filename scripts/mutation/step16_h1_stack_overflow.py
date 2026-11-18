# Step 16, H1: StackOverflowError caught at ShezGuard's own extras read sites (AndroidExtras).
# DEVICE-ONLY: the proving tests are src/androidTest (overflow tests never run under Robolectric), and
# run_mutants.py runs JVM tests only. These mutants were applied by hand on emulators (docs/MUTATION_CHECKS.md);
# this file records the exact edits. Each edit replaces one `catch (StackOverflowError)` clause with the `}` that
# closes the preceding catch block.
FILE = "shezguard-core/src/main/java/com/shezguard/core/android/AndroidExtras.kt"
TESTS = []  # device-only: DeepNestingEvaluateDeviceTest, DeepNestingNestedIntentDeviceTest, DeepNestingOnNewIntentDeviceTest
MUTANTS = [
    {
        "id": "h1a",
        "description": "Bundle.get read site no longer catches StackOverflowError (valueAt)",
        "edits": [(
            "        } catch (e: StackOverflowError) { // H1: the platform's recursive read of a deeply nested container\n            ExtraValue.Unreadable\n        }\n",
            "        }\n",
        )],
    },
    {
        "id": "h1b",
        "description": "IntentSanitizer.sanitize on a nested intent no longer catches StackOverflowError (sanitizeNested)",
        "edits": [(
            "        } catch (e: StackOverflowError) { // H1: IntentSanitizer reads the nested intent's extras\n            NestedResult.Denied\n        }\n",
            "        }\n",
        )],
    },
    {
        "id": "h1c",
        "description": "keySet() read site no longer catches StackOverflowError (read); eager unparcelling is API 24-32 only",
        "edits": [(
            "        } catch (e: StackOverflowError) { // H1: on API 24-32, keySet() unparcels every value eagerly\n            return ExtrasRead.Unreadable\n        }\n",
            "        }\n",
        )],
    },
]
