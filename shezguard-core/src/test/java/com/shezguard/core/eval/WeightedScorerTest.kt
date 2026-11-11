package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.RiskScore
import com.shezguard.core.Severity
import com.shezguard.core.Tier
import com.shezguard.core.UriComponent
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.CALLER_NOT_ALLOWED
import com.shezguard.core.ViolationCode.CALLER_UNIDENTIFIED
import com.shezguard.core.ViolationCode.DOMAIN_NOT_VERIFIED
import com.shezguard.core.ViolationCode.DOMAIN_VERIFICATION_UNAVAILABLE
import com.shezguard.core.ViolationCode.PARAM_UNKNOWN_IGNORED
import com.shezguard.core.ViolationCode.URI_NON_CANONICAL
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.ScoreWeights
import com.shezguard.core.policy.Threshold
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/** SPEC 5.2 weighted scoring (step 7). Pure JVM. */
class WeightedScorerTest {

    private fun v(code: ViolationCode, field: Field = Field.CallerSignal) = Violation(code, "ep", field)

    private fun ep(block: Int = 70, weights: Map<ViolationCode, Int> = emptyMap()) =
        EntryPointPolicy("ep", threshold = Threshold(block), scoreWeights = ScoreWeights(weights))

    private fun score(violations: List<Violation>, policy: EntryPointPolicy = ep()): RiskScore =
        Scorer.WEIGHTED.score(violations.filter { it.tier == Tier.SOFT }, policy)

    private fun outcome(violations: List<Violation>, policy: EntryPointPolicy = ep()): Outcome =
        OutcomeRule.decide(violations, score(violations, policy), policy.threshold)

    private val softCodes = ViolationCode.entries.filter { it.tier == Tier.SOFT }

    // ---- Default weights (proposal (a)) ------------------------------------------------

    @Test
    fun defaultWeightsAreTheApprovedTable() {
        val expected = mapOf(
            URI_NON_CANONICAL to 5, PARAM_UNKNOWN_IGNORED to 5, CALLER_UNIDENTIFIED to 5,
            DOMAIN_VERIFICATION_UNAVAILABLE to 5, CALLER_NOT_ALLOWED to 50, DOMAIN_NOT_VERIFIED to 50,
        )
        assertEquals(expected.keys, softCodes.toSet())
        expected.forEach { (code, w) -> assertEquals(code.id, w, ScoreWeights.DEFAULT.weightOf(code)) }
    }

    @Test
    fun severityWeightsAreTheApprovedTable() {
        assertEquals(listOf(5, 25, 50, 100), Severity.entries.map { it.defaultWeight })
    }

    // ---- Counting, order and explanation ---------------------------------------------

    @Test
    fun eachSoftCodeCountsOnceWithOccurrences() {
        // Seven ignored tracking parameters must not add up to a block (proposal (a)1).
        val tracking = listOf("utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid")
        val violations = tracking.map { v(PARAM_UNKNOWN_IGNORED, Field.Param(it, declared = false)) }
        val s = score(violations)
        assertEquals(5, s.total)
        assertEquals(1, s.contributions.size)
        assertEquals(7, s.contributions[0].occurrences)
        assertEquals(violations[0], s.contributions[0].violation)
        assertEquals(Outcome.ALLOW, outcome(violations))
    }

    @Test
    fun contributionsFollowFirstOccurrenceOrderAndRecordTheThreshold() {
        val s = score(
            listOf(v(DOMAIN_NOT_VERIFIED), v(URI_NON_CANONICAL, Field.UriPart(UriComponent.PATH)), v(DOMAIN_NOT_VERIFIED)),
            ep(block = 60),
        )
        assertEquals(listOf(DOMAIN_NOT_VERIFIED, URI_NON_CANONICAL), s.contributions.map { it.violation.code })
        assertEquals(listOf(50, 5), s.contributions.map { it.weight })
        assertEquals(listOf(2, 1), s.contributions.map { it.occurrences })
        assertEquals(55, s.total)
        assertEquals(60, s.threshold)
    }

    @Test
    fun zeroWeightSignalIsNotAContribution() {
        val s = score(listOf(v(URI_NON_CANONICAL), v(CALLER_NOT_ALLOWED)), ep(weights = mapOf(URI_NON_CANONICAL to 0)))
        assertEquals(listOf(CALLER_NOT_ALLOWED), s.contributions.map { it.violation.code })
        assertEquals(50, s.total)
    }

    @Test
    fun noSoftSignalsScoreZeroWithThreshold() {
        val s = score(emptyList(), ep(block = 42))
        assertEquals(0, s.total)
        assertTrue(s.contributions.isEmpty())
        assertEquals(42, s.threshold)
    }

    @Test
    fun overridesReplaceDefaults() {
        assertEquals(30, score(listOf(v(URI_NON_CANONICAL)), ep(weights = mapOf(URI_NON_CANONICAL to 30))).total)
    }

    // ---- Arithmetic edges (proposal (d)) ---------------------------------------------

    /** A policy where URI_NON_CANONICAL alone weighs exactly [w]. */
    private fun only(w: Int, block: Int) = ep(block, mapOf(URI_NON_CANONICAL to w))

    @Test
    fun scoreZeroNeverBlocks() {
        for (block in 1..100) assertEquals(Outcome.ALLOW, outcome(listOf(v(URI_NON_CANONICAL)), only(0, block)))
    }

    @Test
    fun scoreOneBelowThresholdDoesNotBlock() {
        for (block in 1..100) assertEquals(Outcome.ALLOW, outcome(listOf(v(URI_NON_CANONICAL)), only(block - 1, block)))
    }

    @Test
    fun scoreAtThresholdBlocks() {
        for (block in 1..100) assertEquals(Outcome.BLOCK, outcome(listOf(v(URI_NON_CANONICAL)), only(block, block)))
    }

    @Test
    fun scoreHundredBlocksAtEveryThreshold() {
        for (block in 1..100) assertEquals(Outcome.BLOCK, outcome(listOf(v(URI_NON_CANONICAL)), only(100, block)))
    }

    @Test
    fun sumIsCappedAtHundredWithoutChangingTheOutcome() {
        val all100 = softCodes.associateWith { 100 }
        val s = score(softCodes.map { v(it) }, ep(block = 100, weights = all100))
        assertEquals(RiskScore.MAX, s.total)
        assertEquals(600, s.contributions.sumOf { it.weight })
        assertEquals(Outcome.BLOCK, outcome(softCodes.map { v(it) }, ep(block = 100, weights = all100)))
    }

    @Test
    fun scoreBlockWinsOverSanitize() {
        val removable = v(ViolationCode.PARAM_UNKNOWN_DROPPED, Field.Param("x", false))
        assertEquals(Outcome.SANITIZE, outcome(listOf(v(URI_NON_CANONICAL), removable), only(69, 70)))
        assertEquals(Outcome.BLOCK, outcome(listOf(v(URI_NON_CANONICAL), removable), only(70, 70)))
    }

    // ---- Exhaustive default combinations (author condition 2) -------------------------

    /** Pairs the evaluator can never emit together (by definition; step 8 must prove it). */
    private val exclusive = listOf(
        setOf(CALLER_UNIDENTIFIED, CALLER_NOT_ALLOWED),
        setOf(DOMAIN_NOT_VERIFIED, DOMAIN_VERIFICATION_UNAVAILABLE),
    )

    @Test
    fun defaultWeightsOverAllEmittableSubsetsOfSoftSignals() {
        assertEquals(6, softCodes.size)
        val high = softCodes.filter { it.defaultSeverity == Severity.HIGH }.toSet()
        assertEquals(setOf(CALLER_NOT_ALLOWED, DOMAIN_NOT_VERIFIED), high)
        val t = Threshold.DEFAULT.block

        var checked = 0
        var maximalOneHigh = 0
        for (mask in 0 until (1 shl softCodes.size)) {
            val subset = softCodes.filterIndexed { i, _ -> mask and (1 shl i) != 0 }.toSet()
            if (exclusive.any { subset.containsAll(it) }) continue
            checked++
            val s = score(subset.map { v(it) })
            val blocked = outcome(subset.map { v(it) }) == Outcome.BLOCK
            val highs = subset.count { it in high }
            when {
                subset.size == 1 -> assertTrue("single signal $subset blocks (score ${s.total})", !blocked)
                highs >= 2 -> assertTrue("two HIGH signals $subset do not block (score ${s.total})", blocked)
                else -> assertTrue("$subset blocks with fewer than two HIGH signals (score ${s.total})", !blocked)
            }
            // One HIGH plus every compatible LOW: the largest such sets.
            val lows = softCodes.filter { it !in high }.filter { low -> exclusive.none { it.contains(low) && it.any { h -> h in subset && h in high } } }
            if (highs == 1 && subset.containsAll(lows)) {
                maximalOneHigh++
                assertTrue("one HIGH + all compatible LOW $subset reaches ${s.total} >= $t", s.total < t)
            }
        }
        assertEquals("64 subsets minus 28 with an exclusive pair", 36, checked)
        assertEquals(2, maximalOneHigh)
    }

    // ---- No weights can unblock HARD (approved test) ---------------------------------

    @Test
    fun noCombinationOfWeightsTurnsHardIntoAllowOrSanitize() {
        val r = Random(0x5C_0E7)
        val hard = ViolationCode.entries.filter { it.tier == Tier.HARD }
        val removable = ViolationCode.entries.filter { it.tier == Tier.REMOVABLE }
        repeat(5000) {
            val weights = when (r.nextInt(4)) {
                0 -> softCodes.associateWith { 0 }
                1 -> softCodes.associateWith { 100 }
                else -> softCodes.filter { r.nextBoolean() }.associateWith { r.nextInt(0, 101) }
            }
            val policy = ep(block = r.nextInt(1, 101), weights = weights)
            val violations = buildList {
                repeat(r.nextInt(1, 4)) { add(v(hard[r.nextInt(hard.size)])) }
                repeat(r.nextInt(0, 3)) { add(v(removable[r.nextInt(removable.size)])) }
                repeat(r.nextInt(0, 8)) { add(v(softCodes[r.nextInt(softCodes.size)])) }
            }.shuffled(r)
            assertEquals(Outcome.BLOCK, outcome(violations, policy))
        }
    }

    @Test
    fun scoreCanOnlyAddBlock() {
        // Monotone: for any weights, the outcome with the score is the outcome without it, or Block.
        val r = Random(0x30_70)
        repeat(3000) {
            val policy = ep(block = r.nextInt(1, 101), weights = softCodes.filter { r.nextBoolean() }.associateWith { r.nextInt(0, 101) })
            val violations = buildList {
                if (r.nextInt(3) == 0) add(v(ViolationCode.EXTRA_NOT_ALLOWED, Field.Extra("x", false)))
                repeat(r.nextInt(0, 6)) { add(v(softCodes[r.nextInt(softCodes.size)])) }
            }
            val without = OutcomeRule.decide(violations, RiskScore.ZERO, policy.threshold)
            val with = outcome(violations, policy)
            assertTrue("$without -> $with", with == without || with == Outcome.BLOCK)
        }
    }

    // ---- Determinism -----------------------------------------------------------------

    @Test
    fun sameSoftSignalsAlwaysGiveTheSameScore() {
        val r = Random(0xDE7)
        repeat(1000) {
            val violations = List(r.nextInt(0, 8)) { v(softCodes[r.nextInt(softCodes.size)]) }
            val policy = ep(block = r.nextInt(1, 101))
            assertEquals(score(violations, policy), score(violations.toList(), policy))
        }
        assertNotEquals(score(listOf(v(URI_NON_CANONICAL))), score(listOf(v(CALLER_NOT_ALLOWED))))
    }
}
