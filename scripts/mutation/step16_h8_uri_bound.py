# Step 16, H8: upper bound on Limits.maxUriLength, checked when the policy is built.
FILE = "shezguard-core/src/main/java/com/shezguard/core/policy/IntentPolicy.kt"
TESTS = ["com.shezguard.core.policy.PolicyModelTest", "com.shezguard.core.policy.PolicyDslTest"]
MUTANTS = [
    {
        "id": "h8",
        "description": "maxUriLength upper bound removed",
        "edits": [("        require(maxUriLength <= MAX_URI_LENGTH_BOUND) { \"maxUriLength must be at most $MAX_URI_LENGTH_BOUND\" }\n", "")],
    },
]
