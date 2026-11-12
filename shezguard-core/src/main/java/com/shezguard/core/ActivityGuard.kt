package com.shezguard.core

import android.app.Activity
import android.content.Intent
import androidx.annotation.CheckResult
import com.shezguard.core.policy.IntentPolicy

/**
 * An intent that [ActivityGuard] allowed or sanitized, returned to the app for use.
 *
 * `toString()` never includes the intent, because `Intent.toString()` prints the data URI.
 *
 * @property intent the intent the app may use; also the activity's `getIntent()` after the guard
 * ran. For an Allow it is the delivered intent; for a Sanitize it is the sanitized copy.
 * @property data the canonical, validated data URI, or `null` if the intent has none. Read
 * parameters from here, never from `intent.getData()`.
 * @property decision the [Decision.Allow] or [Decision.Sanitize] behind this result.
 */
public class CheckedIntent internal constructor(
    public val intent: Intent,
    public val data: GuardedUri?,
    public val decision: Decision,
) {
    init {
        require(decision !is Decision.Block) { "a blocked intent is never returned to the app" }
    }

    override fun toString(): String = "CheckedIntent(decision=$decision)"
}

/**
 * Optional Activity helper (SPEC section 7.2, step 10): evaluates the intent an Activity receives
 * against the entry point named by its [GuardedEntryPoint] annotation, and finishes safely on
 * Block. The core API ([ShezGuard.evaluate]) does not need it.
 *
 * ```kotlin
 * val guard = ActivityGuard(policy) // app-owned; build it from code, not from injected fields
 *
 * @GuardedEntryPoint("product")
 * class ProductActivity : AppCompatActivity() {
 *     override fun onCreate(savedInstanceState: Bundle?) {
 *         val checked = guard.onCreate(this)                  // before super.onCreate
 *         super.onCreate(checked?.let { savedInstanceState }) // on Block: no state restore
 *         if (checked == null) return
 *         // ... use checked.data
 *     }
 *
 *     override fun onNewIntent(intent: Intent) {
 *         val checked = guard.onNewIntent(this, intent) ?: return
 *         super.onNewIntent(checked.intent)
 *         // ... use checked.data
 *     }
 * }
 * ```
 *
 * **The app must use the result.** `null` means Block, and the app must return at once. Nothing
 * in the language enforces this: `@CheckResult` makes Android Lint warn when the result is ignored,
 * and the nullable type means [CheckedIntent.data] cannot be reached without handling `null`, but
 * code that ignores the result, or reads `getIntent()` before the guard, still compiles.
 *
 * **Why before `super.onCreate`.** `super.onCreate` restores fragments and other saved state, which
 * can read `getIntent()`. After process death `getIntent()` is the raw launch intent again
 * (`docs/PAPER_NOTES.md` N14), so the guard must run first. Passing `null` to `super.onCreate` on
 * Block keeps saved state from being restored by the base class. The guard does not touch the
 * activity's window, views or saved state.
 *
 * **Recreation.** [onCreate] evaluates every time, including with a non-null
 * `savedInstanceState`; no decision is cached. A recreation can therefore block where the first
 * launch was allowed: for example under `allowedPackages(requireReliableIdentity = true)` after a
 * task is restored without its reliable caller identity, or after a policy change
 * (`docs/LIMITATIONS.md` L34).
 *
 * **What it cannot do.** It runs inside the app, after the OS has started (or brought to the front)
 * the activity and its task. It controls only whether the app uses the intent's data.
 *
 * Holds only [policy]; no global state. The policy's audit sink receives exactly one event per call.
 * Call it on the main thread, as the lifecycle methods are.
 *
 * @param policy the app's policy.
 */
public class ActivityGuard(private val policy: IntentPolicy) {

    /**
     * Evaluates `activity.getIntent()` as [Delivery.LAUNCH]. Call it first in `onCreate`, before
     * `super.onCreate`, on every creation, including recreation.
     *
     * - **Allow:** `getIntent()` is left unchanged; returns it.
     * - **Sanitize:** `getIntent()` is replaced with the sanitized copy (`setIntent`), so later
     *   reads, including Navigation deep link handling, see only checked data; returns the copy.
     * - **Block:** calls `setResult(RESULT_CANCELED, null)`, replaces `getIntent()` with an empty
     *   `Intent()` (never with the blocked intent), calls `finish()`, and returns `null`. The app must
     *   still call `super.onCreate` (with `null`) and then return. The platform then skips `onStart`
     *   and `onResume` and goes to `onDestroy`.
     *
     * A `null` `getIntent()` is evaluated as an empty `Intent()`.
     *
     * @return the checked intent, or `null` on Block.
     */
    @CheckResult
    public fun onCreate(activity: Activity): CheckedIntent? {
        val intent = activity.intent ?: Intent()
        return when (val d = decide(activity, intent, Delivery.LAUNCH)) {
            is Decision.Allow -> CheckedIntent(intent, d.data, d)
            is Decision.Sanitize -> {
                activity.intent = d.sanitizedIntent
                CheckedIntent(d.sanitizedIntent, d.data, d)
            }
            is Decision.Block -> {
                activity.setResult(Activity.RESULT_CANCELED, null)
                activity.intent = Intent()
                activity.finish()
                null
            }
        }
    }

    /**
     * Evaluates [intent], the argument of `onNewIntent`, as [Delivery.NEW_INTENT]. It never reads
     * `getIntent()`. Call it first in `onNewIntent`, before `super.onNewIntent`.
     *
     * - **Allow:** `getIntent()` becomes [intent]; returns it.
     * - **Sanitize:** `getIntent()` becomes the sanitized copy; returns it.
     * - **Block:** nothing is changed and the activity is **not** finished; returns `null`. The app
     *   must return without calling `super.onNewIntent`, so listeners registered on the base class
     *   do not see the blocked intent. Finishing would let any app that can reach this activity end
     *   the user's running session with one bad intent; the trade-off is that a rejected link gives
     *   the user no visible response unless the app adds one (`docs/LIMITATIONS.md` L34).
     *
     * No reliable caller identity is available for this delivery (`docs/PAPER_NOTES.md` N12), so
     * under `allowedPackages(requireReliableIdentity = true)` every `onNewIntent` is blocked.
     *
     * @return the checked intent, or `null` on Block.
     */
    @CheckResult
    public fun onNewIntent(activity: Activity, intent: Intent): CheckedIntent? =
        when (val d = decide(activity, intent, Delivery.NEW_INTENT)) {
            is Decision.Allow -> {
                activity.intent = intent
                CheckedIntent(intent, d.data, d)
            }
            is Decision.Sanitize -> {
                activity.intent = d.sanitizedIntent
                CheckedIntent(d.sanitizedIntent, d.data, d)
            }
            is Decision.Block -> null
        }

    private fun decide(activity: Activity, intent: Intent, delivery: Delivery): Decision {
        val name = entryPointName(activity.javaClass) ?: return ShezGuard.blockUnannotated(policy)
        return ShezGuard.evaluate(activity, intent, delivery, policy, name)
    }

    public companion object {
        /**
         * The `Decision.entryPoint` (and audit event entry point) reported when the activity has no
         * usable [GuardedEntryPoint] name.
         */
        public const val UNANNOTATED: String = "<unannotated>"

        /** The annotation on [cls] itself (not inherited); `null` if missing, empty or exempt. */
        internal fun entryPointName(cls: Class<*>): String? {
            val a = try {
                cls.getAnnotation(GuardedEntryPoint::class.java)
            } catch (e: RuntimeException) {
                null
            } ?: return null
            return a.name.takeIf { !a.exempt && it.isNotEmpty() }
        }
    }
}
