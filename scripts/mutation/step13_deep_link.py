"""Step 13 mutants of the deep link advice (issue 6, threat 4). Target: DeepLinkDetector.kt."""

MODULE = "shezguard-lint"
TASK = "test"
FILE = "shezguard-lint/src/main/java/com/shezguard/lint/DeepLinkDetector.kt"
TESTS = ["com.shezguard.lint.DeepLinkDetectorTest"]

MUTANTS = [
    {
        "id": "d1",
        "description": "BROWSABLE not required (any VIEW filter reported)",
        "edits": [("        if (BROWSABLE !in categories) return\n", "")],
    },
    {
        "id": "d2",
        "description": "custom schemes not reported",
        "edits": [("for (scheme in schemes.filter { it !in web }.distinct()) {", "for (scheme in emptyList<String>()) {")],
    },
    {
        "id": "d3",
        "description": "https without autoVerify also reported (duplicates the built-in AppLinkWarning)",
        "edits": [("if (web.isNotEmpty() && autoVerify != null && autoVerify != \"true\") {",
                   "if (web.isNotEmpty() && autoVerify != \"true\") {")],
    },
    {
        "id": "d4",
        "description": "autoVerify=\"false\" accepted",
        "edits": [("if (web.isNotEmpty() && autoVerify != null && autoVerify != \"true\") {",
                   "if (web.isNotEmpty() && autoVerify == null && false) {")],
    },
]
