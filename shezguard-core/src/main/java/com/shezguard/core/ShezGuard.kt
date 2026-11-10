package com.shezguard.core

import android.content.Intent
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
 * **Scope (v1, step 5b).** Only the data URI and its query parameters are checked. Extras,
 * nested intents, risk scoring and caller signals are added in later steps; until then
 * ShezGuard does not read extras at all, so an intent's extras are neither checked nor
 * unparcelled here.
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
     * `intent.getData()`.
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
        val e = Evaluator.evaluate(policy, name) { readData(intent) }
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

    private fun sanitize(intent: Intent, e: Evaluation): Decision {
        val raw = e.dataString ?: return blocked(Evaluator.failed(e.entryPoint))
        val copy = IntentCopy.withData(intent, QueryRemoval.remove(raw, e.droppedNames))
        val rebuilt = copy.data
        if (!SanitizeCheck.verify(e, copy.dataString, rebuilt?.let(::AndroidUriView))) {
            return blocked(Evaluator.failed(e.entryPoint))
        }
        return Decision.Sanitize(copy, e.entryPoint, e.violations, e.score, e.guarded)
    }

    private fun blocked(e: Evaluation): Decision = Decision.Block(e.entryPoint, e.violations, e.score)
}
