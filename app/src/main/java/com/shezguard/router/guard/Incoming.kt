package com.shezguard.router.guard

import android.content.Intent

/**
 * What an entry point may read from the intent it received, as handed out by [EntryGuard].
 *
 * RULE (step 11, author condition 1): demo activities read data and extras **only** through
 * `Incoming`: URI parameters through [param], extras through [intent] (`incoming.intent`). They never
 * call `getIntent()` / `activity.intent` themselves. That keeps every sink identical in both flavors;
 * the flavor's [EntryGuard] alone decides what [intent] and [param] return.
 *
 * @property intent the intent the activity may use (vulnerable flavor: the raw delivered intent).
 */
class Incoming(val intent: Intent, private val read: (String) -> String?) {
    /** The value of the URI query parameter [name], as the flavor's [EntryGuard] reads it. */
    fun param(name: String): String? = read(name)
}
