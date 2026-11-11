package com.shezguard.core

import android.content.Intent
import com.shezguard.core.android.AndroidExtras
import com.shezguard.core.android.AndroidUriView
import com.shezguard.core.android.IntentCopy
import com.shezguard.core.eval.Evaluation
import com.shezguard.core.eval.Evaluator
import com.shezguard.core.eval.QueryRemoval
import com.shezguard.core.eval.SanitizeCheck
import com.shezguard.core.eval.UriInput
import com.shezguard.core.policy.IntentPolicy

/**
 * The public entry point: validates an incoming intent against an entry point policy.
 *
 * **Scope (v1, step 6).** The data URI, its query parameters, the extras and nested intents
 * in extras are checked. Risk scoring and caller signals are added in later steps.
 *
 * **Reading extras deserialises them.** To find nested intents anywhere in the extras,
 * ShezGuard reads every extra value from a copy of the Bundle. Any code a hostile
 * `Parcelable` or `Serializable` runs while being read therefore runs here, even for an
 * intent that is then blocked (`docs/LIMITATIONS.md` L1, L27). An exception while reading is
 * caught and becomes `EXTRAS_UNPARCEL_FAILED`; the caller's Bundle is not read or changed.
 */
public object ShezGuard {

    /**
     * Evaluates [intent] against the entry point [entryPointName] in [policy].
     *
     * - An unregistered entry point name is blocked (`ENTRY_POINT_UNKNOWN`, deny by default).
     * - All violations are collected, not just the first.
     * - [intent] is never modified. A Sanitize decision carries a modified **copy**.
     * - The same input always gives the same decision.
     * - This function does not throw for any intent: a `RuntimeException` during evaluation
     *   becomes a Block with `EVALUATION_FAILED`. `Error`s are not caught.
     *
     * Read the URI's data from `Decision.Allow.data` / `Decision.Sanitize.data`, never from
     * `intent.getData()`. After a Sanitize, read extras and nested intents from
     * `Decision.Sanitize.sanitizedIntent`, which holds only the values ShezGuard checked and,
     * for `Nested.AllowSanitized` keys, `IntentSanitizer`'s output. After a Block, do not read
     * the intent at all.
     *
     * @param intent the intent the component received.
     * @param policy the app's policy.
     * @param entryPointName the name of the policy entry point for this component.
     */
    public fun evaluate(intent: Intent, policy: IntentPolicy, entryPointName: String): Decision = try {
        decide(intent, policy, entryPointName)
    } catch (e: RuntimeException) {
        blocked(Evaluator.failed(entryPointName))
    }

    private fun decide(intent: Intent, policy: IntentPolicy, name: String): Decision {
        val e = Evaluator.evaluate(policy, name, extras = AndroidExtras(intent)) { readData(intent) }
        return when (e.outcome) {
            Outcome.BLOCK -> blocked(e)
            Outcome.ALLOW -> Decision.Allow(intent, name, e.violations, e.score, e.guarded)
            Outcome.SANITIZE -> sanitize(intent, e)
        }
    }

    /** Reads only the data URI; never extras (`docs/CANONICALISER_TESTS.md`, "Input contract"). */
    private fun readData(intent: Intent): UriInput? {
        val uri = intent.data ?: return null
        val dataString = intent.dataString ?: return null
        return UriInput(dataString, AndroidUriView(uri))
    }

    /**
     * One copy of the intent carries every removal: the dropped query parameters (step 5b) and
     * the rebuilt extras (step 6). Each part is checked after it is built; a mismatch fails closed.
     */
    private fun sanitize(intent: Intent, e: Evaluation): Decision {
        val failed = { blocked(Evaluator.failed(e.entryPoint)) }
        val dropsParams = e.droppedNames.isNotEmpty()
        val rebuild = e.extrasRebuild
        if (!dropsParams && rebuild == null) return failed()
        val copy = if (dropsParams) {
            val raw = e.dataString ?: return failed()
            IntentCopy.withData(intent, QueryRemoval.remove(raw, e.droppedNames)).also { c ->
                if (!SanitizeCheck.verify(e, c.dataString, c.data?.let(::AndroidUriView))) return failed()
            }
        } else {
            IntentCopy.copy(intent)
        }
        if (rebuild != null && !IntentCopy.replaceExtras(copy, rebuild)) return failed()
        return Decision.Sanitize(copy, e.entryPoint, e.violations, e.score, e.guarded)
    }

    private fun blocked(e: Evaluation): Decision = Decision.Block(e.entryPoint, e.violations, e.score)
}
