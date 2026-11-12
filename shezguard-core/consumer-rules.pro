# ShezGuard consumer R8/ProGuard rules, applied to apps that depend on :shezguard-core.

# Step 10: ActivityGuard reads @GuardedEntryPoint from the activity class at runtime.
# - keep the attribute that stores runtime-visible annotations;
# - keep the annotation type and its members (name(), exempt()) unrenamed;
# - for every annotated class that survives shrinking, keep its annotations. allowshrinking and
#   allowobfuscation: these rules do not keep unused classes or names; activities are kept by the
#   manifest rules AAPT generates.
# If a build strips the annotation anyway, ActivityGuard blocks the activity
# (ENTRY_POINT_NOT_ANNOTATED): a loud failure, not a silent bypass.
# Not yet checked on a minified build: that check is part of step 12 (docs/LIMITATIONS.md L36).
-keepattributes RuntimeVisibleAnnotations
-keep @interface com.shezguard.core.GuardedEntryPoint { *; }
-keep,allowshrinking,allowobfuscation,allowoptimization @com.shezguard.core.GuardedEntryPoint class *
