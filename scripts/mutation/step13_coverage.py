"""Step 13 mutants of the coverage detector (docs/MUTATION_CHECKS.md). Target: ShezGuardDetector.kt
(issues 1, 2/2b, 3, dependency and non-activity reports). Each edit's `old` text must occur exactly once."""

MODULE = "shezguard-lint"
TASK = "test"
FILE = "shezguard-lint/src/main/java/com/shezguard/lint/ShezGuardDetector.kt"
TESTS = ["com.shezguard.lint.CoverageDetectorTest", "com.shezguard.lint.GuardCallDetectorTest"]

MUTANTS = [
    {
        "id": "c1",
        "description": "implicit export (intent filter, targetSdk < 31) not detected",
        "edits": [("exported == null && filters.isNotEmpty() && targetSdk < 31 ->",
                   "false && exported == null && filters.isNotEmpty() && targetSdk < 31 ->")],
    },
    {
        "id": "c2",
        "description": "BROWSABLE filters ignored",
        "edits": [("val browsable = filters.any { f -> children(f, \"category\").any { it.androidAttr(\"name\") == BROWSABLE } }",
                   "val browsable = false")],
    },
    {
        "id": "c3",
        "description": "exempt = true treated as covered without checking for a name",
        "edits": [("            exempt && name.isNotEmpty() ->\n", "            false ->\n")],
    },
    {
        "id": "c4",
        "description": "empty name accepted",
        "edits": [(
            "            name.isEmpty() ->\n"
            "                \"`@GuardedEntryPoint` has an empty name and is not exempt, so the guard blocks every launch. \" +\n"
            "                    \"Name the entry point, or set `exempt = true` if the activity reads no intent data.\"\n"
            "            !NAME.matches(name) ->",
            "            name.isEmpty() -> null\n"
            "            !NAME.matches(name) ->",
        )],
    },
    {
        "id": "c5",
        "description": "any annotated name treated as declared by the policy",
        "edits": [("            if (name in seen.names) continue\n", "            continue\n")],
    },
    {
        "id": "c6",
        "description": "non-constant entryPoint names do not downgrade a missing name (Error instead of Warning)",
        "edits": [("                seen.nonConstant.isNotEmpty() -> context.report(", "                false -> context.report(")],
    },
    {
        "id": "c7",
        "description": "checkDependencies ignored: no policy found is always a Warning",
        "edits": [("                seen.names.isEmpty() && !checkDependencies -> context.report(",
                   "                seen.names.isEmpty() -> context.report(")],
    },
    {
        "id": "c8",
        "description": "dependency activities treated as the app's own",
        "edits": [("            if (target !in seen.classes) {", "            if (false) {")],
    },
    {
        "id": "c9",
        "description": "an annotation alone counts as coverage of any activity: unannotated activities not reported",
        "edits": [("            if (annotation == null) {", "            if (false) {")],
    },
    {
        "id": "c10",
        "description": "android:permission no longer exempts a service/receiver/provider",
        "edits": [("            if (permission) return\n", "")],
    },
    {
        "id": "c11",
        "description": "guard call inside an exempt activity not reported",
        "edits": [("        if (exempt) {\n            context.report(", "        if (false) {\n            context.report(")],
    },
]
