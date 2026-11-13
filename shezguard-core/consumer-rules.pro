# ShezGuard consumer R8/ProGuard rules, applied to apps that depend on :shezguard-core.

# Step 10: ActivityGuard reads @GuardedEntryPoint from the activity class at runtime.
# - keep the attribute that stores runtime-visible annotations;
# - keep the annotation type and its members (name(), exempt()) unrenamed;
# - for every annotated class that survives shrinking, keep its annotations. allowshrinking and
#   allowobfuscation: these rules do not keep unused classes or names; activities are kept by the
#   manifest rules AAPT generates.
# If a build strips the annotation anyway, ActivityGuard blocks the activity
# (ENTRY_POINT_NOT_ANNOTATED): a loud failure, not a silent bypass.
# Checked in step 12 on one minified build: the protected demo app (:app, build type "minified") built
# with AGP's default R8 and proguard-android-optimize.txt, run on an API 34 emulator. The annotation and
# its values survived on every annotated activity, and no ENTRY_POINT_NOT_ANNOTATED occurred in any
# attack or benign run (docs/LIMITATIONS.md L36). These rules do not cover the app's own Serializable
# classes: an app must keep those completely itself (docs/LIMITATIONS.md L40, docs/PAPER_NOTES.md N15).
-keepattributes RuntimeVisibleAnnotations
-keep @interface com.shezguard.core.GuardedEntryPoint { *; }
-keep,allowshrinking,allowobfuscation,allowoptimization @com.shezguard.core.GuardedEntryPoint class *
