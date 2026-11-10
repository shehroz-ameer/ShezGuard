package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.GuardedUri
import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.Tier
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode.DATA_FORBIDDEN
import com.shezguard.core.ViolationCode.DATA_MISSING
import com.shezguard.core.ViolationCode.ENTRY_POINT_UNKNOWN
import com.shezguard.core.ViolationCode.EVALUATION_FAILED
import com.shezguard.core.canon.CanonResult
import com.shezguard.core.canon.CanonicalUri
import com.shezguard.core.canon.UriCanonicalizer
import com.shezguard.core.policy.Data
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.validate.UriPolicyValidator

/**
 * The result of the pure pipeline, before it is turned into a public `Decision`.
 *
 * @property policy the entry point policy, or `null` if the name is not registered.
 * @property canonical the canonical URI, if the intent had one and it canonicalised.
 * @property retainedQuery the canonical query minus parameters dropped under `Unknown.Drop`.
 * @property droppedNames names of the parameters dropped under `Unknown.Drop`.
 * @property dataString the raw data string that was canonicalised, if any.
 */
internal class Evaluation(
    val entryPoint: String,
    val policy: EntryPointPolicy?,
    val violations: List<Violation>,
    val score: RiskScore,
    val outcome: Outcome,
    val canonical: CanonicalUri? = null,
    val guarded: GuardedUri? = null,
    val retainedQuery: List<Pair<String, String>> = emptyList(),
    val droppedNames: Set<String> = emptySet(),
    val dataString: String? = null,
)

/**
 * SPEC section 5 for URI and parameter checks (step 5b). Pure Kotlin; the intent is seen
 * only through [UriInput]. Later steps add stages (extras, caller signals) and a real
 * [Scorer]; the outcome rule stays in [OutcomeRule].
 *
 * Order: deny unknown entry points; apply the data rule; canonicalise; compare with the
 * platform parser; check the policy. All violations are collected, except that a URI that
 * fails canonicalisation cannot be compared or policy-checked (there is no canonical form),
 * and a URI on a `Data.Forbidden` entry point is not examined at all (author decision 2).
 *
 * Fail closed: any `RuntimeException` (for example from a `Uri` accessor) gives a single
 * `EVALUATION_FAILED` violation. `Error`s propagate.
 */
internal object Evaluator {

    fun evaluate(
        policy: IntentPolicy,
        entryPoint: String,
        scorer: Scorer = Scorer.NONE,
        input: () -> UriInput?,
    ): Evaluation = try {
        run(policy, entryPoint, scorer, input)
    } catch (e: RuntimeException) {
        failed(entryPoint)
    }

    fun failed(entryPoint: String): Evaluation = Evaluation(
        entryPoint = entryPoint,
        policy = null,
        violations = listOf(Violation(EVALUATION_FAILED, entryPoint, Field.EntryPoint)),
        score = RiskScore.ZERO,
        outcome = Outcome.BLOCK,
    )

    private fun run(policy: IntentPolicy, entryPoint: String, scorer: Scorer, input: () -> UriInput?): Evaluation {
        // Deny by default, before the intent is read at all.
        val ep = policy[entryPoint] ?: return Evaluation(
            entryPoint = entryPoint,
            policy = null,
            violations = listOf(Violation(ENTRY_POINT_UNKNOWN, entryPoint, Field.EntryPoint)),
            score = RiskScore.ZERO,
            outcome = Outcome.BLOCK,
        )

        val out = LinkedHashSet<Violation>()
        val whole = Field.UriPart(UriComponent.WHOLE)
        val data = input()
        var canonical: CanonicalUri? = null
        var guarded: GuardedUri? = null
        var retained: List<Pair<String, String>> = emptyList()
        var dropped: Set<String> = emptySet()

        when {
            data == null -> if (ep.data == Data.Required) out.add(Violation(DATA_MISSING, ep.name, whole))
            ep.data == Data.Forbidden -> out.add(Violation(DATA_FORBIDDEN, ep.name, whole))
            else -> when (val r = UriCanonicalizer.canonicalize(data.dataString, ep.limits)) {
                is CanonResult.Rejected -> r.findings.forEach {
                    out.add(Violation(it.code, ep.name, Field.UriPart(it.component)))
                }
                is CanonResult.Ok -> {
                    r.findings.forEach { out.add(Violation(it.code, ep.name, Field.UriPart(it.component))) }
                    out.addAll(ParserMismatch.check(r.uri, data.view, ep))
                    val validation = UriPolicyValidator.validate(r.uri, ep)
                    out.addAll(validation.violations)
                    canonical = r.uri
                    retained = validation.retainedQuery
                    val retainedNames = retained.mapTo(HashSet()) { it.first }
                    dropped = r.uri.query.mapNotNullTo(LinkedHashSet()) { (n, _) -> n.takeIf { it !in retainedNames } }
                    guarded = guardedUri(r.uri, retained, ep)
                }
            }
        }

        val violations = out.toList()
        val score = scorer.score(violations.filter { it.tier == Tier.SOFT }, ep)
        return Evaluation(
            entryPoint = entryPoint,
            policy = ep,
            violations = violations,
            score = score,
            outcome = OutcomeRule.decide(violations, score, ep.threshold),
            canonical = canonical,
            guarded = guarded,
            retainedQuery = retained,
            droppedNames = dropped,
            dataString = data?.dataString,
        )
    }

    /** Only declared parameters are exposed (author decision 3). */
    private fun guardedUri(c: CanonicalUri, retained: List<Pair<String, String>>, ep: EntryPointPolicy): GuardedUri {
        val declared = LinkedHashMap<String, MutableList<String>>()
        for ((name, value) in retained) {
            if (ep.param(name) != null) declared.getOrPut(name) { ArrayList() }.add(value)
        }
        return GuardedUri(c.scheme, c.host, c.port, c.pathSegments.toList(), c.hasTrailingSlash, c.fragment, declared)
    }
}

/**
 * Self-check for a Sanitize decision: the rebuilt URI must canonicalise to exactly the
 * original canonical URI with the dropped parameters removed, and the platform parser must
 * agree with it. Any other result means [QueryRemoval] changed something it must not, and
 * the caller fails closed with `EVALUATION_FAILED`.
 */
internal object SanitizeCheck {
    fun verify(evaluation: Evaluation, rebuilt: String?, view: UriView?): Boolean {
        val original = evaluation.canonical ?: return false
        val policy = evaluation.policy ?: return false
        if (rebuilt == null || view == null) return false
        val r = UriCanonicalizer.canonicalize(rebuilt, policy.limits) as? CanonResult.Ok ?: return false
        return r.uri == original.copy(query = evaluation.retainedQuery) &&
            ParserMismatch.check(r.uri, view, policy).isEmpty()
    }
}
