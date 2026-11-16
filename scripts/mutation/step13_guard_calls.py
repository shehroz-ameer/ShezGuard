"""Step 13 mutants of the guard-call heuristics (issues 4 and 5). Target: GuardCallHeuristics.kt."""

MODULE = "shezguard-lint"
TASK = "test"
FILE = "shezguard-lint/src/main/java/com/shezguard/lint/GuardCallHeuristics.kt"
TESTS = ["com.shezguard.lint.GuardCallDetectorTest"]

MUTANTS = [
    {
        "id": "g1",
        "description": "reads of the Kotlin `intent` property before the guard ignored",
        "edits": [("if (guardMethod == \"onCreate\" && node.identifier == \"intent\" && isActivityGetIntent(context, node.resolve())) {",
                   "if (false) {")],
    },
    {
        "id": "g2",
        "description": "super.onCreate / super.onNewIntent before the guard ignored",
        "edits": [("if (node.receiver is USuperExpression && node.methodName == guardMethod) {", "if (false) {")],
    },
    {
        "id": "g3",
        "description": "order comparison inverted (flags calls AFTER the guard)",
        "edits": [("if (offset != null && offset < guardStart &&", "if (offset != null && offset > guardStart &&")],
    },
    {
        "id": "g4",
        "description": "`!!` on the guard result counted as a null check",
        "edits": [("            parent is KtPostfixExpression && parent.operationToken == KtTokens.EXCLEXCL -> {",
                   "            parent is KtPostfixExpression && parent.operationToken == KtTokens.EXCLEXCL -> return\n            false -> {")],
    },
    {
        "id": "g5",
        "description": "any use of the stored result counts as a null check",
        "edits": [("if (node.identifier == name && isNullCheckUse(node)) checked = true",
                   "if (node.identifier == name) checked = true")],
    },
    {
        "id": "g6",
        "description": "explicit getIntent() calls before the guard ignored",
        "edits": [("} else if (guardMethod == \"onCreate\" && node.methodName == \"getIntent\" && isActivityGetIntent(context, node.resolve())) {",
                   "} else if (false) {")],
    },
    {
        "id": "g7",
        "description": "both getIntent branches removed (Kotlin `intent` property and explicit calls)",
        "edits": [
            ("} else if (guardMethod == \"onCreate\" && node.methodName == \"getIntent\" && isActivityGetIntent(context, node.resolve())) {",
             "} else if (false) {"),
            ("if (guardMethod == \"onCreate\" && node.identifier == \"intent\" && isActivityGetIntent(context, node.resolve())) {",
             "if (false) {"),
        ],
    },
]
