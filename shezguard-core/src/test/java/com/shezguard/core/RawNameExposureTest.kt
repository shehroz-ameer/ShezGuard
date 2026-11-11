package com.shezguard.core

import android.content.Intent
import com.shezguard.core.eval.EvalFixtures.viewIntent
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.EntryPointBuilder
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.lang.reflect.Modifier
import java.util.IdentityHashMap

/**
 * Author condition 1 (step 9 follow-up): no public property or method of Field, Violation,
 * ScoreContribution, RiskScore or Decision returns an undeclared, attacker-chosen name.
 *
 * The walk calls every public, non-synthetic, zero-argument instance method of every ShezGuard
 * object it reaches (Kotlin getters, `componentN`, `toString`, ...), recursing into ShezGuard
 * types, collections, maps and arrays. It does not descend into Android objects: the original
 * intent (`Decision.Allow.intent`) and the sanitized copy carry the raw URI by design, because the
 * app owns them. Kotlin `internal` members compile to public, name-mangled JVM methods; they are
 * hidden here only because they are also `@JvmSynthetic`. Robolectric, SDK 34.
 */
@RunWith(RobolectricTestRunner::class)
class RawNameExposureTest {

    private companion object {
        const val CANARY = "zqxcanary"
    }

    /** Every path from [root] to a string containing [CANARY]. */
    private fun leaks(root: Any): List<String> {
        val seen = IdentityHashMap<Any, Unit>()
        val out = mutableListOf<String>()
        var calls = 0

        fun visit(o: Any?, path: String) {
            when (o) {
                null, is Number, is Boolean, is Enum<*> -> Unit
                is CharSequence -> if (o.contains(CANARY, ignoreCase = true)) out += "$path = $o"
                is Map<*, *> -> o.forEach { (k, v) -> visit(k, "$path{key}"); visit(v, "$path[$k]") }
                is Iterable<*> -> o.forEachIndexed { i, e -> visit(e, "$path[$i]") }
                is Array<*> -> o.forEachIndexed { i, e -> visit(e, "$path[$i]") }
                else -> {
                    if (!o.javaClass.name.startsWith("com.shezguard.")) return
                    if (seen.put(o, Unit) != null) return
                    for (m in o.javaClass.methods) {
                        if (m.parameterCount != 0 || Modifier.isStatic(m.modifiers) || m.isSynthetic || m.isBridge) continue
                        if (m.declaringClass == Any::class.java || m.name == "hashCode") continue
                        val r = try {
                            m.invoke(o)
                        } catch (e: ReflectiveOperationException) {
                            continue
                        }
                        calls++
                        visit(r, "$path.${m.name}()")
                    }
                }
            }
        }
        visit(root, root.javaClass.simpleName)
        assertTrue("the walk called no method on $root", calls > 0)
        return out
    }

    private fun EntryPointBuilder.web(unknown: Unknown) {
        allowSchemes("https")
        allowHosts("example.com")
        anyPath()
        param("q") { string(CharClass.TEXT) }
        unknownParams(unknown)
        extras { allow("title", ExtraType.STRING) }
    }

    private val policy = intentPolicy {
        entryPoint("drop") { web(Unknown.Drop) }
        entryPoint("ignore") { web(Unknown.Ignore) }
        entryPoint("strict") { web(Unknown.Block) }
    }

    private fun decisions(): List<Decision> {
        val uri = "https://example.com/p?q=x&$CANARY=1&utm_$CANARY=2"
        return listOf("drop", "ignore", "strict").flatMap { ep ->
            listOf(
                viewIntent(uri),
                viewIntent("https://example.com/p?q=x").putExtra(CANARY, "v").putExtra("title", "t"),
                Intent().putExtra("title", "t").putExtra("${CANARY}key", 1),
            ).map { ShezGuard.evaluate(it, policy, ep) }
        }
    }

    @Test
    fun noPublicApiReturnsAnUndeclaredName() {
        val undeclaredParam = Violation(ViolationCode.PARAM_UNKNOWN_IGNORED, "p", Field.Param(CANARY, declared = false))
        val roots = listOf<Any>(
            Field.Param(CANARY, declared = false),
            Field.Extra(CANARY, declared = false),
            undeclaredParam,
            Violation(ViolationCode.EXTRA_NOT_ALLOWED, "p", Field.Extra(CANARY, declared = false)),
            ScoreContribution(undeclaredParam, 5, occurrences = 2),
            RiskScore.of(listOf(ScoreContribution(undeclaredParam, 5)), threshold = 70),
        ) + decisions()
        val ds = roots.filterIsInstance<Decision>()
        assertEquals("every outcome is walked", Outcome.entries.toSet(), ds.map { it.outcome }.toSet())
        assertTrue("an undeclared canary name reached a violation", ds.any { d ->
            d.violations.any { v -> v.field == Field.Param(CANARY, declared = false) || v.field == Field.Extra(CANARY, declared = false) }
        })
        for (r in roots) assertEquals("$r", emptyList<String>(), leaks(r))
    }

    @Test
    fun theWalkFindsADeclaredName() {
        // Declared names come from the policy and are public by design; the walk must find them.
        assertTrue(leaks(Field.Param(CANARY, declared = true)).isNotEmpty())
        assertTrue(leaks(Violation(ViolationCode.EXTRA_WRONG_TYPE, "p", Field.Extra(CANARY, declared = true))).isNotEmpty())
    }

    @Test
    fun declaredNameIsShownOnlyForPolicyNames() {
        assertEquals("id", Field.Param("id", declared = true).declaredName)
        assertEquals("title", Field.Extra("title", declared = true).declaredName)
        assertNull(Field.Param(CANARY, declared = false).declaredName)
        assertNull(Field.Extra(CANARY, declared = false).declaredName)
        assertFalse(Field.Param(CANARY, declared = false).declared)
    }

    @Test
    fun fieldsKeepValueEqualityAndRedactedToString() {
        assertEquals(Field.Param("a", false), Field.Param("a", false))
        assertEquals(Field.Param("a", false).hashCode(), Field.Param("a", false).hashCode())
        assertNotEquals(Field.Param("a", false), Field.Param("b", false))
        assertNotEquals(Field.Param("a", false), Field.Param("a", true))
        assertFalse((Field.Param("a", false) as Field) == Field.Extra("a", false))
        assertEquals("param:<undeclared>", Field.Param(CANARY, false).toString())
        assertEquals("extra:<undeclared>", Field.Extra(CANARY, false).toString())
        assertEquals("param:id", Field.Param("id", true).toString())
    }
}
