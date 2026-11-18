# Step 16, H6: unmodifiable copies in IntentPolicy / EntryPointPolicy.
FILE = "shezguard-core/src/main/java/com/shezguard/core/policy/IntentPolicy.kt"
TESTS = ["com.shezguard.core.policy.PolicyImmutabilityTest"]
MUTANTS = [
    {
        "id": "h6a",
        "description": "IntentPolicy.entryPoints is the mutable map from associateBy again",
        "edits": [("        this.entryPoints = entryPoints.associateBy { it.name }.frozen() // step 16, H6\n",
                   "        this.entryPoints = entryPoints.associateBy { it.name }\n")],
    },
    {
        "id": "h6b",
        "description": "EntryPointPolicy.hosts keeps the caller's set (no copy)",
        "edits": [("    public val hosts: Set<HostPattern> = hosts.frozen()\n", "    public val hosts: Set<HostPattern> = hosts\n")],
    },
]
