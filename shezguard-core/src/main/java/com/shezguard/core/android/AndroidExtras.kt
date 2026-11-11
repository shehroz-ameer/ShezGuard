package com.shezguard.core.android

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentSender
import android.os.Bundle
import android.util.SparseArray
import com.shezguard.core.eval.ExtraEntry
import com.shezguard.core.eval.ExtraValue
import com.shezguard.core.eval.ExtrasRead
import com.shezguard.core.eval.ExtrasSource
import com.shezguard.core.eval.KeptExtra
import com.shezguard.core.eval.NestedKind
import com.shezguard.core.eval.NestedResult
import com.shezguard.core.policy.ExtrasRule

/**
 * Reads an intent's extras for the extras stage (step 6 proposal (a), `docs/PAPER_NOTES.md` N6, N7).
 *
 * Calls, in order, and nothing else:
 * 1. `intent.getExtras()`, once. It returns `new Bundle(mExtras)` on API 24–34: a copy of the
 *    parcelled bytes, so the caller's Bundle is never unparcelled or truncated by ShezGuard.
 * 2. `keySet()` on that copy, once. This unparcels the copy: on API 24–32 every value is
 *    deserialised here; on 33–34 Parcelable, Serializable and container values stay lazy.
 * 3. `get(key)` (deprecated, but the only accessor that shows the real type) for every key,
 *    which on 33–34 deserialises that key's lazy value.
 * 4. The same for nested Bundles, up to [ExtrasRule.MAX_NESTING_DEPTH] containers.
 *
 * Every read catches `RuntimeException` (including `BadParcelableException`) and records the
 * part as unreadable. A failed Bundle is never read again (N6). `Error`s are not caught.
 */
internal class AndroidExtras(private val intent: Intent) : ExtrasSource {

    override fun read(maxKeys: Int): ExtrasRead {
        val bundle: Bundle
        val keys: List<String?>
        try {
            bundle = intent.extras ?: return ExtrasRead.Absent
            keys = ArrayList(bundle.keySet())
        } catch (e: RuntimeException) {
            return ExtrasRead.Unreadable
        }
        if (keys.size > maxKeys) return ExtrasRead.TooMany(keys.size)
        return ExtrasRead.Entries(keys.map { ExtraEntry(it, valueAt(bundle, it, depth = 0)) })
    }

    override fun sanitizeNested(handle: Any, sanitizer: NestedIntentSanitizer): NestedResult {
        val nested = handle as? Intent ?: return NestedResult.Denied
        return try {
            // The message carries raw values (docs/PAPER_NOTES.md N9): it is discarded unread.
            val output = sanitizer.sanitizer.sanitize(nested) { _ -> }
            when {
                // IntentSanitizer replaces a rejected component instead of removing it: a rewrite (SPEC 4.1).
                output.component != nested.component -> NestedResult.Denied
                leavesNestedIntent(output) -> NestedResult.Denied
                else -> NestedResult.Sanitized(output)
            }
        } catch (e: RuntimeException) {
            NestedResult.Denied
        }
    }

    /** IntentSanitizer copies allowed extras as they are; another Intent among them is not sanitized. */
    private fun leavesNestedIntent(output: Intent): Boolean {
        val read = AndroidExtras(output).read(Int.MAX_VALUE)
        if (read !is ExtrasRead.Entries) return read !is ExtrasRead.Absent
        return read.entries.any { e -> e.value.any { it is ExtraValue.NestedIntent || it === ExtraValue.Unreadable || it === ExtraValue.TooDeep } }
    }

    private fun ExtraValue.any(p: (ExtraValue) -> Boolean): Boolean =
        p(this) || (this is ExtraValue.Container && elements.any { it.any(p) })

    internal companion object {

        @Suppress("DEPRECATION")
        private fun valueAt(bundle: Bundle, key: String?, depth: Int): ExtraValue = try {
            classify(bundle.get(key), depth)
        } catch (e: RuntimeException) {
            ExtraValue.Unreadable
        }

        /** [depth] is the number of containers around [v] inside one top-level extra. */
        private fun classify(v: Any?, depth: Int): ExtraValue = when {
            v == null -> ExtraValue.Null
            v is String -> ExtraValue.Str(v)
            v is Boolean -> ExtraValue.Bool(v)
            v is Int -> ExtraValue.I32(v)
            v is Long -> ExtraValue.I64(v)
            v is Float -> ExtraValue.F32(v)
            v is Double -> ExtraValue.F64(v)
            v.javaClass == Array<String>::class.java -> {
                @Suppress("UNCHECKED_CAST")
                ExtraValue.StrArray(v as Array<String?>)
            }
            v is IntArray -> ExtraValue.IntArr(v)
            v is LongArray -> ExtraValue.LongArr(v)
            v is Intent -> ExtraValue.NestedIntent(NestedKind.INTENT, v)
            v is PendingIntent -> ExtraValue.NestedIntent(NestedKind.PENDING_INTENT, v)
            v is IntentSender -> ExtraValue.NestedIntent(NestedKind.INTENT_SENDER, v)
            isContainer(v) -> if (depth >= ExtrasRule.MAX_NESTING_DEPTH) ExtraValue.TooDeep else container(v, depth + 1)
            else -> ExtraValue.Other
        }

        private fun isContainer(v: Any): Boolean =
            v is Bundle || v is Array<*> || v is List<*> || v is Map<*, *> || v is SparseArray<*>

        private fun container(v: Any, depth: Int): ExtraValue = try {
            ExtraValue.Container(
                when (v) {
                    is Bundle -> ArrayList(v.keySet()).map { valueAt(v, it, depth) }
                    is Array<*> -> v.map { classify(it, depth) }
                    is List<*> -> v.map { classify(it, depth) }
                    is Map<*, *> -> v.entries.flatMap { (k, value) -> listOf(classify(k, depth), classify(value, depth)) }
                    is SparseArray<*> -> (0 until v.size()).map { classify(v.valueAt(it), depth) }
                    else -> listOf(ExtraValue.Other)
                },
            )
        } catch (e: RuntimeException) {
            ExtraValue.Unreadable
        }

        /**
         * The extras of a Sanitize copy: exactly the values ShezGuard read and checked, plus the
         * sanitizer's output for nested-intent keys. Arrays are copied so the caller's objects are
         * never shared. Returns `null` when nothing is kept.
         */
        fun bundleOf(kept: List<KeptExtra>): Bundle? {
            if (kept.isEmpty()) return null
            val b = Bundle(kept.size)
            for (k in kept) {
                when (val v = k.value) {
                    ExtraValue.Null -> b.putString(k.key, null)
                    is ExtraValue.Str -> b.putString(k.key, v.value)
                    is ExtraValue.Bool -> b.putBoolean(k.key, v.value)
                    is ExtraValue.I32 -> b.putInt(k.key, v.value)
                    is ExtraValue.I64 -> b.putLong(k.key, v.value)
                    is ExtraValue.F32 -> b.putFloat(k.key, v.value)
                    is ExtraValue.F64 -> b.putDouble(k.key, v.value)
                    is ExtraValue.StrArray -> b.putStringArray(k.key, v.value.copyOf())
                    is ExtraValue.IntArr -> b.putIntArray(k.key, v.value.copyOf())
                    is ExtraValue.LongArr -> b.putLongArray(k.key, v.value.copyOf())
                    is ExtraValue.NestedIntent -> b.putParcelable(k.key, k.nestedOutput as Intent)
                    else -> throw IllegalStateException("not a keepable extra")
                }
            }
            return b
        }
    }
}
