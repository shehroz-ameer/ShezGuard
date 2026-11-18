# Step 16, H8 (decision): query parameter count capped before any android.net.Uri accessor runs.
FILE = "shezguard-core/src/main/java/com/shezguard/core/canon/UriCanonicalizer.kt"
TESTS = ["com.shezguard.core.eval.ParameterFloodTest", "com.shezguard.core.canon.UriCanonicalizerTest"]
MUTANTS = [
    {
        "id": "h8b",
        "description": "the parameter-count cap is removed (no PARAM_TOO_MANY)",
        "edits": [("            f.add(PARAM_TOO_MANY, QUERY)\n", "")],
    },
]
