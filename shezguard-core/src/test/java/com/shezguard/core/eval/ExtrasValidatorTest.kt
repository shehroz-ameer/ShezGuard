package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.EXTRAS_TOO_DEEP
import com.shezguard.core.ViolationCode.EXTRAS_TOO_MANY
import com.shezguard.core.ViolationCode.EXTRAS_UNPARCEL_FAILED
import com.shezguard.core.ViolationCode.EXTRA_NOT_ALLOWED
import com.shezguard.core.ViolationCode.EXTRA_TOO_LARGE
import com.shezguard.core.ViolationCode.EXTRA_WRONG_TYPE
import com.shezguard.core.ViolationCode.NESTED_INTENT_DENIED
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.ExtrasRule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pure extras rules (SPEC 5.4) on hand-built value trees, on the JVM without Android.
 * Android reading, unparcelling and `IntentSanitizer` are covered by the Robolectric tests.
 */
class ExtrasValidatorTest {

    private val rule = ExtrasRule(
        allowed = mapOf(
            "title" to ExtraType.STRING, "count" to ExtraType.INT, "big" to ExtraType.LONG,
            "on" to ExtraType.BOOLEAN, "ratio" to ExtraType.FLOAT, "pi" to ExtraType.DOUBLE,
            "tags" to ExtraType.STRING_ARRAY, "ids" to ExtraType.INT_ARRAY, "longs" to ExtraType.LONG_ARRAY,
        ),
    )
    private val ep = EntryPointPolicy("share", extras = rule)

    /** Nested sanitizing is never reached under `Nested.Deny`. */
    private object NoSanitize : ExtrasSource {
        override fun read(maxKeys: Int): ExtrasRead = error("not used")
        override fun sanitizeNested(handle: Any, sanitizer: NestedIntentSanitizer): NestedResult = error("not used")
    }

    private fun validate(vararg entries: Pair<String?, ExtraValue>, policy: EntryPointPolicy = ep) =
        ExtrasValidator.validate(ExtrasRead.Entries(entries.map { ExtraEntry(it.first, it.second) }), policy, NoSanitize)

    private fun codes(o: ExtrasOutcome) = o.violations.map { it.code }.toSet()

    private val intent = ExtraValue.NestedIntent(NestedKind.INTENT, Any())

    // ---- Allowed keys and types ------------------------------------------------------

    @Test
    fun allowsEveryDeclaredTypeWithoutRebuilding() {
        val o = validate(
            "title" to ExtraValue.Str("hi"), "count" to ExtraValue.I32(1), "big" to ExtraValue.I64(2),
            "on" to ExtraValue.Bool(true), "ratio" to ExtraValue.F32(1f), "pi" to ExtraValue.F64(3.0),
            "tags" to ExtraValue.StrArray(arrayOf("a", null)), "ids" to ExtraValue.IntArr(intArrayOf(1)),
            "longs" to ExtraValue.LongArr(longArrayOf(1)),
        )
        assertEquals(emptyList<Any>(), o.violations)
        assertNull("nothing removed, so the extras are not rebuilt", o.rebuilt)
    }

    @Test
    fun blocksTypeConfusionUnderAllowedKey() {
        val o = validate("count" to ExtraValue.Str("1"), "title" to ExtraValue.I32(1), "tags" to ExtraValue.Other)
        assertEquals(setOf(EXTRA_WRONG_TYPE), codes(o))
        assertEquals(3, o.violations.size)
        assertTrue(o.violations.all { (it.field as Field.Extra).declared })
    }

    @Test
    fun blocksObjectArrayPosingAsStringArray() {
        // An Object[] of strings arrives as a container, not as String[] (VAL_OBJECTARRAY).
        val o = validate("tags" to ExtraValue.Container(listOf(ExtraValue.Str("a"))))
        assertEquals(setOf(EXTRA_WRONG_TYPE), codes(o))
    }

    @Test
    fun nullValueUnderAllowedKeyCountsAsAbsent() {
        assertEquals(emptyList<Any>(), validate("title" to ExtraValue.Null, "ids" to ExtraValue.Null).violations)
    }

    // ---- Size limits -----------------------------------------------------------------

    @Test
    fun blocksOversizedStringExtraButAllowsTheLimit() {
        assertEquals(emptyList<Any>(), validate("title" to ExtraValue.Str("a".repeat(256))).violations)
        assertEquals(setOf(EXTRA_TOO_LARGE), codes(validate("title" to ExtraValue.Str("a".repeat(257)))))
    }

    @Test
    fun blocksOversizedArrayExtras() {
        assertEquals(emptyList<Any>(), validate("ids" to ExtraValue.IntArr(IntArray(64))).violations)
        val o = validate(
            "ids" to ExtraValue.IntArr(IntArray(65)),
            "longs" to ExtraValue.LongArr(LongArray(65)),
            "tags" to ExtraValue.StrArray(arrayOfNulls(65)),
        )
        assertEquals(listOf(EXTRA_TOO_LARGE, EXTRA_TOO_LARGE, EXTRA_TOO_LARGE), o.violations.map { it.code })
    }

    @Test
    fun blocksOversizedStringArrayElementOncePerKey() {
        val o = validate("tags" to ExtraValue.StrArray(arrayOf("ok", "a".repeat(257), "b".repeat(300))))
        assertEquals(listOf(EXTRA_TOO_LARGE), o.violations.map { it.code })
    }

    @Test
    fun customLimitsApply() {
        val small = EntryPointPolicy(
            "s",
            extras = ExtrasRule(mapOf("t" to ExtraType.STRING, "a" to ExtraType.INT_ARRAY), maxStringLength = 3, maxArrayLength = 2),
        )
        val o = validate("t" to ExtraValue.Str("abcd"), "a" to ExtraValue.IntArr(IntArray(3)), policy = small)
        assertEquals(listOf(EXTRA_TOO_LARGE, EXTRA_TOO_LARGE), o.violations.map { it.code })
    }

    // ---- Unknown keys ----------------------------------------------------------------

    @Test
    fun removesUnknownExtraKeyAndKeepsTheCheckedValues() {
        val o = validate("title" to ExtraValue.Str("hi"), "evil" to ExtraValue.Str("x"), null to ExtraValue.Str("y"))
        assertEquals(listOf(EXTRA_NOT_ALLOWED, EXTRA_NOT_ALLOWED), o.violations.map { it.code })
        assertEquals(listOf(Field.Extra("evil", false), Field.Extra("", false)), o.violations.map { it.field })
        assertEquals(listOf("title"), o.rebuilt!!.map { it.key })
    }

    @Test
    fun tooManyExtrasStopsTheStage() {
        val o = ExtrasValidator.validate(ExtrasRead.TooMany(17), ep, NoSanitize)
        assertEquals(listOf(Pair(EXTRAS_TOO_MANY, Field.Extras)), o.violations.map { it.code to it.field })
    }

    @Test
    fun unreadableBundleIsOneViolation() {
        val o = ExtrasValidator.validate(ExtrasRead.Unreadable, ep, NoSanitize)
        assertEquals(listOf(Pair(EXTRAS_UNPARCEL_FAILED, Field.Extras)), o.violations.map { it.code to it.field })
    }

    @Test
    fun unreadableValueIsReportedWithoutGuessingItsType() {
        val o = validate("title" to ExtraValue.Unreadable, "evil" to ExtraValue.Unreadable)
        assertEquals(
            listOf(
                Pair(EXTRAS_UNPARCEL_FAILED, Field.Extra("title", true)),
                Pair(EXTRAS_UNPARCEL_FAILED, Field.Extra("evil", false)),
                Pair(EXTRA_NOT_ALLOWED, Field.Extra("evil", false)),
            ),
            o.violations.map { it.code to it.field },
        )
    }

    // ---- Nested intents under Nested.Deny --------------------------------------------

    @Test
    fun blocksNestedIntentRedirectionInEveryShape() {
        val shapes = listOf(
            intent,
            ExtraValue.NestedIntent(NestedKind.PENDING_INTENT, Any()),
            ExtraValue.NestedIntent(NestedKind.INTENT_SENDER, Any()),
            ExtraValue.Container(listOf(ExtraValue.Str("a"), intent)),
            ExtraValue.Container(listOf(ExtraValue.Container(listOf(ExtraValue.Container(listOf(intent)))))),
        )
        for (s in shapes) {
            val o = validate("evil" to s)
            assertEquals(listOf(EXTRA_NOT_ALLOWED, NESTED_INTENT_DENIED), o.violations.map { it.code })
        }
    }

    @Test
    fun blocksNestedIntentUnderAllowedKeyAsWrongTypeAndDenied() {
        assertEquals(setOf(EXTRA_WRONG_TYPE, NESTED_INTENT_DENIED), codes(validate("title" to intent)))
    }

    @Test
    fun blocksExtrasNestedBeyondDepthLimit() {
        val o = validate("evil" to ExtraValue.Container(listOf(ExtraValue.TooDeep)))
        assertEquals(listOf(EXTRAS_TOO_DEEP, EXTRA_NOT_ALLOWED), o.violations.map { it.code })
    }

    @Test
    fun containerWithoutIntentIsOnlyNotAllowed() {
        val o = validate("evil" to ExtraValue.Container(listOf(ExtraValue.Str("a"), ExtraValue.Other)))
        assertEquals(listOf(EXTRA_NOT_ALLOWED), o.violations.map { it.code })
    }

    @Test
    fun absentExtrasHaveNoViolations() {
        val o = ExtrasValidator.validate(ExtrasRead.Absent, ep, NoSanitize)
        assertEquals(emptyList<ViolationCode>(), o.violations)
        assertNull(o.rebuilt)
    }
}
