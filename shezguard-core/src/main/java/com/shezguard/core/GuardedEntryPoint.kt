package com.shezguard.core

/**
 * Names the policy entry point that guards an Activity (SPEC section 9, step 10).
 *
 * ```kotlin
 * @GuardedEntryPoint("product")
 * class ProductActivity : AppCompatActivity() { ... }
 * ```
 *
 * [ActivityGuard] reads it at runtime from the activity's exact class and evaluates the incoming
 * intent against the entry point [name] in its policy. The build-time check (step 13) reads it from
 * source to match exported and `BROWSABLE` components to policies.
 *
 * - **Not inherited.** Only the annotation on the activity's own class counts, so a subclass never
 *   silently takes its parent's entry point; an unannotated subclass is denied.
 * - **Deny by default.** [ActivityGuard] blocks an activity with no annotation, an empty [name], or
 *   `exempt = true` (`ENTRY_POINT_NOT_ANNOTATED`). A [name] that is not in the policy is blocked as
 *   `ENTRY_POINT_UNKNOWN`.
 * - **Minified builds.** The library's consumer R8/ProGuard rules keep this annotation on classes.
 *   If a build strips it anyway, every guarded activity is blocked: the failure is loud, not
 *   silent. Checked in step 12 on one minified build: the protected demo app built with R8 (AGP's
 *   default R8, `proguard-android-optimize.txt`) on an API 34 emulator. The annotation and its values
 *   survived on every annotated activity, and no `ENTRY_POINT_NOT_ANNOTATED` occurred. Evidence:
 *   `docs/LIMITATIONS.md` L36. The same build showed that the app's own keep rules for Serializable
 *   extras must keep the whole class (`docs/LIMITATIONS.md` L40, `docs/PAPER_NOTES.md` N15).
 *
 * @property name the entry point name in the `intentPolicy { entryPoint(name) { ... } }` DSL.
 * @property exempt `true` marks a component that deliberately has no policy, such as a launcher
 * activity, so the build-time check accepts it. Calling [ActivityGuard] on an exempt activity is a
 * programming error and is blocked.
 */
@MustBeDocumented
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS)
public annotation class GuardedEntryPoint(
    public val name: String = "",
    public val exempt: Boolean = false,
)
