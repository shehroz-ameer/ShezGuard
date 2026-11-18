# Step 16, H2: the exact getPath() comparison in the parser-mismatch check.
FILE = "shezguard-core/src/main/java/com/shezguard/core/eval/ParserMismatch.kt"
TESTS = ["com.shezguard.core.eval.PathAccessorAgreementTest"]
MUTANTS = [
    {
        "id": "h2",
        "description": "getPath() no longer compared (only path segments), so '//' is a soft signal again",
        "edits": [(
            "        if (if (emptyPath) path != null && path != \"\" && path != \"/\" else path != c.path) add(UriComponent.PATH)\n",
            "",
        )],
    },
]
