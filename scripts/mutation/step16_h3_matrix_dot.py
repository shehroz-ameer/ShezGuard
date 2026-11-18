# Step 16, H3: `..;` / `.;` segments (the part before the first ';') rejected as dot segments.
FILE = "shezguard-core/src/main/java/com/shezguard/core/canon/UriCanonicalizer.kt"
TESTS = ["com.shezguard.core.canon.UriCanonicalizerTest", "com.shezguard.core.eval.ShezGuardEvaluateTest"]
MUTANTS = [
    {
        "id": "h3",
        "description": "the part before ';' is no longer checked as a dot segment",
        "edits": [(
            "            val beforeParams = piece.substringBefore(';')\n",
            "            val beforeParams = piece\n",
        )],
    },
]
