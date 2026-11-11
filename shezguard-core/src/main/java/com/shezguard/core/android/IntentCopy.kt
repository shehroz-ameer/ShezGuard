package com.shezguard.core.android

import android.content.Intent
import android.net.Uri
import com.shezguard.core.eval.KeptExtra

/** Builds the sanitized copy of an intent (step 5b proposal (d)1 and (d)3, step 6 proposal (b)). */
internal object IntentCopy {
    /**
     * Copies [original] with `Intent(Intent)` and replaces only its data URI.
     *
     * The caller's intent is not modified. On API 24 to 34 the copy constructor copies the
     * extras with `new Bundle(o.mExtras)`, a shallow copy that duplicates the parcelled
     * bytes without unparcelling them (`docs/PAPER_NOTES.md` N5). `setDataAndType` is used
     * because `setData` would clear the MIME type; it sets only the data and type fields.
     * Component, action, flags, categories, package, selector and clip data are kept as copied.
     */
    fun withData(original: Intent, data: String): Intent =
        Intent(original).setDataAndType(Uri.parse(data), original.type)

    /** Copies [original] with `Intent(Intent)`; nothing else changes. */
    fun copy(original: Intent): Intent = Intent(original)

    /**
     * Replaces the extras of [copy] (never the caller's intent) with [kept], the values
     * ShezGuard checked (step 6 proposal (b)). Returns whether the copy now holds exactly the
     * kept keys; any other result makes the caller fail closed.
     */
    fun replaceExtras(copy: Intent, kept: List<KeptExtra>): Boolean {
        copy.replaceExtras(AndroidExtras.bundleOf(kept))
        val keys = copy.extras?.keySet() ?: emptySet<String>()
        return keys == kept.mapTo(HashSet()) { it.key }
    }
}
