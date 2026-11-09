package com.shezguard.core

import android.content.Intent

/**
 * The result of evaluating an intent against an entry point policy.
 *
 * This is the one public model type that holds an Android type, because the caller needs
 * the intent it may use. Everything else about the decision ([violations], [score],
 * [outcome]) is pure Kotlin.
 *
 * Decisions can only be created by ShezGuard (constructors are internal), so app code
 * cannot forge an [Allow].
 *
 * `toString()` never includes the intent, because `Intent.toString()` prints the data
 * URI and that would leak raw input into logs.
 */
public sealed class Decision {

    /** The name of the entry point policy that was evaluated. */
    public abstract val entryPoint: String

    /** Every violation found, in evaluation order. Empty only for a clean [Allow]. */
    public abstract val violations: List<Violation>

    /** The soft-signal risk score and its contributions. */
    public abstract val score: RiskScore

    /** The kind of decision, for code that does not need the payload. */
    public abstract val outcome: Outcome

    /**
     * The intent may be used as received.
     *
     * Only [Tier.SOFT] violations can be present. Read data through ShezGuard's
     * accessors rather than `getIntent()`, so the app uses the values that were checked.
     *
     * @property intent the original intent.
     */
    public class Allow internal constructor(
        public val intent: Intent,
        override val entryPoint: String,
        override val violations: List<Violation>,
        override val score: RiskScore,
    ) : Decision() {
        override val outcome: Outcome = Outcome.ALLOW

        init {
            checkCommon(entryPoint, violations)
            require(violations.all { it.tier == Tier.SOFT }) {
                "Allow may only carry SOFT violations"
            }
        }

        override fun toString(): String = describe()
    }

    /**
     * The intent may be used only in its sanitized form.
     *
     * Sanitizing only removes parts (SPEC section 4.1): unknown parameters, disallowed
     * extras, parts of nested intents. It never rewrites a value. At least one
     * [Tier.REMOVABLE] violation is present, and no [Tier.HARD] one.
     *
     * @property sanitizedIntent a copy of the intent with the removable parts removed.
     */
    public class Sanitize internal constructor(
        public val sanitizedIntent: Intent,
        override val entryPoint: String,
        override val violations: List<Violation>,
        override val score: RiskScore,
    ) : Decision() {
        override val outcome: Outcome = Outcome.SANITIZE

        init {
            checkCommon(entryPoint, violations)
            require(violations.any { it.tier == Tier.REMOVABLE }) {
                "Sanitize needs at least one REMOVABLE violation; otherwise there is nothing to remove"
            }
            require(violations.none { it.tier == Tier.HARD }) { "Sanitize may not carry HARD violations" }
        }

        override fun toString(): String = describe()
    }

    /**
     * The intent must not be used. The app should finish the component safely.
     * At least one violation is always present, so every block is explained.
     */
    public class Block internal constructor(
        override val entryPoint: String,
        override val violations: List<Violation>,
        override val score: RiskScore,
    ) : Decision() {
        override val outcome: Outcome = Outcome.BLOCK

        init {
            checkCommon(entryPoint, violations)
            require(violations.isNotEmpty()) { "Block must explain itself with at least one violation" }
        }

        override fun toString(): String = describe()
    }

    internal fun describe(): String =
        "Decision.${outcome.name.lowercase().replaceFirstChar { it.uppercase() }}(" +
            "entryPoint=$entryPoint, score=${score.total}, violations=$violations)"

    private companion object {
        fun checkCommon(entryPoint: String, violations: List<Violation>) {
            require(violations.all { it.entryPoint == entryPoint }) {
                "every violation must belong to entry point '$entryPoint'"
            }
        }
    }
}
