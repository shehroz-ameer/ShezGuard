"""Step 10 mutants of ActivityGuard (docs/MUTATION_CHECKS.md). Each edit's `old` text must occur
exactly once in FILE; the runner aborts otherwise."""

FILE = "shezguard-core/src/main/java/com/shezguard/core/ActivityGuard.kt"
TESTS = ["com.shezguard.core.activity.ActivityGuardTest"]

_HEADER = "public class ActivityGuard(private val policy: IntentPolicy) {\n"
_LAUNCH = "return when (val d = decide(activity, intent, Delivery.LAUNCH)) {"

MUTANTS = [
    {
        "id": "a1",
        "description": "onCreate Block calls setIntent with the blocked intent",
        "edits": [(
            "                activity.setResult(Activity.RESULT_CANCELED, null)\n                activity.intent = Intent()\n",
            "                activity.setResult(Activity.RESULT_CANCELED, null)\n                activity.intent = intent\n",
        )],
    },
    {
        "id": "a2",
        "description": "onNewIntent Block calls setIntent with the blocked intent",
        "edits": [(
            "            is Decision.Block -> null\n",
            "            is Decision.Block -> { activity.intent = intent; null }\n",
        )],
    },
    {
        "id": "b",
        "description": "a blocked onNewIntent finishes the activity",
        "edits": [(
            "            is Decision.Block -> null\n",
            "            is Decision.Block -> { activity.finish(); null }\n",
        )],
    },
    {
        "id": "c1",
        "description": "onCreate Sanitize does not replace getIntent()",
        "edits": [(
            "                activity.intent = d.sanitizedIntent\n                CheckedIntent(d.sanitizedIntent, d.data, d)\n"
            "            }\n            is Decision.Block -> {\n",
            "                CheckedIntent(d.sanitizedIntent, d.data, d)\n"
            "            }\n            is Decision.Block -> {\n",
        )],
    },
    {
        "id": "c2",
        "description": "onNewIntent Sanitize does not replace getIntent()",
        "edits": [(
            "                activity.intent = d.sanitizedIntent\n                CheckedIntent(d.sanitizedIntent, d.data, d)\n"
            "            }\n            is Decision.Block -> null\n",
            "                CheckedIntent(d.sanitizedIntent, d.data, d)\n"
            "            }\n            is Decision.Block -> null\n",
        )],
    },
    {
        "id": "d1",
        "description": "onCreate caches its decision in the guard, per activity class",
        "edits": [
            (_HEADER, _HEADER + "    private val cache = HashMap<String, Decision>()\n"),
            (_LAUNCH, "return when (val d = cache.getOrPut(activity.javaClass.name) { decide(activity, intent, Delivery.LAUNCH) }) {"),
        ],
    },
    {
        "id": "d2",
        "description": "onCreate caches its decision in the guard, per Intent object",
        "edits": [
            (_HEADER, _HEADER + "    private val cache = java.util.IdentityHashMap<Intent, Decision>()\n"),
            (_LAUNCH, "return when (val d = cache.getOrPut(intent) { decide(activity, intent, Delivery.LAUNCH) }) {"),
        ],
    },
    {
        "id": "d3",
        "description": "onCreate caches its decision in a static field, per activity class",
        "edits": [
            ("    public companion object {\n",
             "    public companion object {\n        private val STATIC_CACHE = HashMap<String, Decision>()\n"),
            (_LAUNCH, "return when (val d = STATIC_CACHE.getOrPut(activity.javaClass.name) { decide(activity, intent, Delivery.LAUNCH) }) {"),
        ],
    },
    {
        "id": "e",
        "description": "a blocked onCreate does not set RESULT_CANCELED",
        "edits": [("                activity.setResult(Activity.RESULT_CANCELED, null)\n", "")],
    },
    {
        "id": "f",
        "description": "onNewIntent evaluates activity.intent instead of its argument",
        "edits": [(
            "when (val d = decide(activity, intent, Delivery.NEW_INTENT)) {",
            "when (val d = decide(activity, activity.intent, Delivery.NEW_INTENT)) {",
        )],
    },
]
