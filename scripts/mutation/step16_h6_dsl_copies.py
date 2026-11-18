# Step 16, H6: the DSL passes unmodifiable copies into the data classes it builds.
FILE = "shezguard-core/src/main/java/com/shezguard/core/policy/PolicyDsl.kt"
TESTS = ["com.shezguard.core.policy.PolicyImmutabilityTest"]
MUTANTS = [
    {
        "id": "h6c",
        "description": "the DSL builds ParamType.OneOf from a mutable set again",
        "edits": [("ParamType.OneOf(list.toSet().frozen())", "ParamType.OneOf(list.toSet())")],
    },
]
