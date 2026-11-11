package com.shezguard.core.eval

import com.shezguard.core.Field
import com.shezguard.core.Violation
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.EXTRAS_TOO_DEEP
import com.shezguard.core.ViolationCode.EXTRAS_TOO_MANY
import com.shezguard.core.ViolationCode.EXTRAS_UNPARCEL_FAILED
import com.shezguard.core.ViolationCode.EXTRA_NOT_ALLOWED
import com.shezguard.core.ViolationCode.EXTRA_TOO_LARGE
import com.shezguard.core.ViolationCode.EXTRA_WRONG_TYPE
import com.shezguard.core.ViolationCode.NESTED_INTENT_DENIED
import com.shezguard.core.ViolationCode.NESTED_INTENT_SANITIZED
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.policy.EntryPointPolicy
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.ExtrasRule
import com.shezguard.core.policy.Nested

/**
 * One extra value as the pure validator sees it. Built by the Android adapter from what
 * `Bundle.get(key)` returned. Values are never printed or put in a violation.
 */
internal sealed class ExtraValue {
    object Null : ExtraValue()
    class Str(val value: String) : ExtraValue()
    class Bool(val value: Boolean) : ExtraValue()
    class I32(val value: Int) : ExtraValue()
    class I64(val value: Long) : ExtraValue()
    class F32(val value: Float) : ExtraValue()
    class F64(val value: Double) : ExtraValue()

    /** Exactly a `String[]` (an `Object[]` or `CharSequence[]` is a [Container] or [Other]). */
    class StrArray(val value: Array<String?>) : ExtraValue()
    class IntArr(val value: IntArray) : ExtraValue()
    class LongArr(val value: LongArray) : ExtraValue()

    /** An `Intent`, `PendingIntent` or `IntentSender`. [handle] is the platform object, opaque here. */
    class NestedIntent(val kind: NestedKind, val handle: Any) : ExtraValue()

    /** A framework container (object array, List, Map keys and values, SparseArray, Bundle) and its elements. */
    class Container(val elements: List<ExtraValue>) : ExtraValue()

    /** Any other type: custom Parcelable or Serializable, CharSequence, other arrays. Its contents are opaque. */
    object Other : ExtraValue()

    /** Reading this value threw. Nothing else is known about it. */
    object Unreadable : ExtraValue()

    /** A container beyond [ExtrasRule.MAX_NESTING_DEPTH]; its contents were not read. */
    object TooDeep : ExtraValue()
}

internal enum class NestedKind { INTENT, PENDING_INTENT, INTENT_SENDER }

/** One top-level extra. [key] is `null` for a Bundle entry with a null key. */
internal class ExtraEntry(val key: String?, val value: ExtraValue)

/** What the Android adapter could read from the intent's extras. */
internal sealed class ExtrasRead {
    /** The intent has no extras. */
    object Absent : ExtrasRead()

    /** Listing the keys threw; no value is known. */
    object Unreadable : ExtrasRead()

    /** More keys than allowed; no value was read. */
    class TooMany(val count: Int) : ExtrasRead()

    class Entries(val entries: List<ExtraEntry>) : ExtrasRead()
}

/** The result of passing one nested Intent through `IntentSanitizer`. */
internal sealed class NestedResult {
    /** [output] is the sanitizer's new Intent, to be forwarded instead of the original. */
    class Sanitized(val output: Any) : NestedResult()

    /** It could not be made safe by removal (see `NESTED_INTENT_DENIED`). */
    object Denied : NestedResult()
}

/** The Android side of the extras stage, so the rules here stay free of Android types. */
internal interface ExtrasSource {
    /** Reads the extras, never more than [maxKeys] values. Must not throw for any intent. */
    fun read(maxKeys: Int): ExtrasRead

    /** Runs [sanitizer] on the nested Intent [handle]. Must not throw. */
    fun sanitizeNested(handle: Any, sanitizer: NestedIntentSanitizer): NestedResult

    companion object {
        /** No extras: used where only the URI is evaluated. */
        val NONE: ExtrasSource = object : ExtrasSource {
            override fun read(maxKeys: Int): ExtrasRead = ExtrasRead.Absent
            override fun sanitizeNested(handle: Any, sanitizer: NestedIntentSanitizer): NestedResult = NestedResult.Denied
        }
    }
}

/**
 * An extra that the sanitized intent keeps: an allowed key with its checked value, or a
 * nested-intent key with the sanitizer's [nestedOutput].
 */
internal class KeptExtra(val key: String, val value: ExtraValue, val nestedOutput: Any? = null)

/**
 * @property rebuilt the extras a Sanitize copy must carry, or `null` if the extras need no
 * change (no removable extras violation).
 */
internal class ExtrasOutcome(val violations: List<Violation>, val rebuilt: List<KeptExtra>?)

/**
 * The extras rules of SPEC 5.4. Two independent rules run on every top-level key:
 * 1. the key rule: allowed key with the right type and size, nested-intent key, or not allowed;
 * 2. the nested-intent rule: any `Intent`, `PendingIntent` or `IntentSender` anywhere in the
 *    value is denied unless it is a single `Intent` under an `AllowSanitized` key.
 * An unreadable or too-deep part of a value is reported before both.
 */
internal object ExtrasValidator {

    private val REBUILD_CODES = setOf(EXTRA_NOT_ALLOWED, NESTED_INTENT_SANITIZED)

    fun validate(read: ExtrasRead, ep: EntryPointPolicy, source: ExtrasSource): ExtrasOutcome {
        val name = ep.name
        return when (read) {
            ExtrasRead.Absent -> ExtrasOutcome(emptyList(), null)
            ExtrasRead.Unreadable -> ExtrasOutcome(listOf(Violation(EXTRAS_UNPARCEL_FAILED, name, Field.Extras)), null)
            is ExtrasRead.TooMany -> ExtrasOutcome(listOf(Violation(EXTRAS_TOO_MANY, name, Field.Extras)), null)
            is ExtrasRead.Entries -> entries(read.entries, ep, source)
        }
    }

    private fun entries(entries: List<ExtraEntry>, ep: EntryPointPolicy, source: ExtrasSource): ExtrasOutcome {
        val rule = ep.extras
        val nested = ep.nestedIntents as? Nested.AllowSanitized
        val out = ArrayList<Violation>()
        val kept = ArrayList<KeptExtra>()

        for (entry in entries) {
            val key = entry.key
            val nestedKey = key != null && nested != null && key in nested.keys
            val type = if (key != null && !nestedKey) rule.allowed[key] else null
            val field = Field.Extra(key ?: "", declared = nestedKey || type != null)
            val v = entry.value
            val before = out.size
            fun add(code: ViolationCode) = out.add(Violation(code, ep.name, field))

            if (v.contains { it === ExtraValue.Unreadable }) add(EXTRAS_UNPARCEL_FAILED)
            if (v.contains { it === ExtraValue.TooDeep }) add(EXTRAS_TOO_DEEP)

            when {
                nestedKey -> when {
                    v === ExtraValue.Null -> kept += KeptExtra(key!!, v)
                    v is ExtraValue.NestedIntent && v.kind == NestedKind.INTENT ->
                        when (val r = source.sanitizeNested(v.handle, nested!!.sanitizer)) {
                            is NestedResult.Sanitized -> {
                                add(NESTED_INTENT_SANITIZED)
                                kept += KeptExtra(key!!, v, r.output)
                            }
                            NestedResult.Denied -> add(NESTED_INTENT_DENIED)
                        }
                    v.contains { it is ExtraValue.NestedIntent } -> add(NESTED_INTENT_DENIED)
                    v === ExtraValue.Unreadable -> Unit
                    else -> add(EXTRA_WRONG_TYPE)
                }
                type != null -> {
                    if (v !== ExtraValue.Unreadable) checkType(v, type, rule)?.let(::add)
                    if (v.contains { it is ExtraValue.NestedIntent }) add(NESTED_INTENT_DENIED)
                    if (out.size == before) kept += KeptExtra(key!!, v)
                }
                else -> {
                    add(EXTRA_NOT_ALLOWED)
                    if (v.contains { it is ExtraValue.NestedIntent }) add(NESTED_INTENT_DENIED)
                }
            }
        }
        val rebuild = out.any { it.code in REBUILD_CODES }
        return ExtrasOutcome(out, if (rebuild) kept else null)
    }

    /** `null` when [v] is acceptable for [type] (a null value counts as absent). */
    private fun checkType(v: ExtraValue, type: ExtraType, rule: ExtrasRule): ViolationCode? {
        if (v === ExtraValue.Null) return null
        val matches = when (type) {
            ExtraType.STRING -> v is ExtraValue.Str
            ExtraType.BOOLEAN -> v is ExtraValue.Bool
            ExtraType.INT -> v is ExtraValue.I32
            ExtraType.LONG -> v is ExtraValue.I64
            ExtraType.FLOAT -> v is ExtraValue.F32
            ExtraType.DOUBLE -> v is ExtraValue.F64
            ExtraType.STRING_ARRAY -> v is ExtraValue.StrArray
            ExtraType.INT_ARRAY -> v is ExtraValue.IntArr
            ExtraType.LONG_ARRAY -> v is ExtraValue.LongArr
        }
        if (!matches) return EXTRA_WRONG_TYPE
        val tooLarge = when (v) {
            is ExtraValue.Str -> v.value.length > rule.maxStringLength
            is ExtraValue.StrArray ->
                v.value.size > rule.maxArrayLength || v.value.any { it != null && it.length > rule.maxStringLength }
            is ExtraValue.IntArr -> v.value.size > rule.maxArrayLength
            is ExtraValue.LongArr -> v.value.size > rule.maxArrayLength
            else -> false
        }
        return if (tooLarge) EXTRA_TOO_LARGE else null
    }

    /** Whether [this] or anything inside it satisfies [p]. Does not descend into nested intents. */
    private fun ExtraValue.contains(p: (ExtraValue) -> Boolean): Boolean =
        p(this) || (this is ExtraValue.Container && elements.any { it.contains(p) })
}
