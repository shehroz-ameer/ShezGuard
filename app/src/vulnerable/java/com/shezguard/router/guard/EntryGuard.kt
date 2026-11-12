package com.shezguard.router.guard

import android.app.Activity
import android.content.Intent

/**
 * Flavor shim (step 11). This is the ONLY flavor-specific source file; every sink is shared.
 *
 * Pass-through: no check at all, and parameters are read the naive way, with
 * `Uri.getQueryParameter` on the raw intent. Never returns `null` (never blocks).
 * In step 11 the `vulnerable` and `protected` copies are identical; step 12 replaces the
 * `protected` copy with `ShezGuard`'s `ActivityGuard`.
 */
object EntryGuard {
    /** Called first in `onCreate`, before `super.onCreate`. `null` would mean: stop. */
    fun onCreate(activity: Activity): Incoming? {
        val intent = activity.intent ?: Intent()
        return Incoming(intent) { name -> intent.data?.getQueryParameter(name) }
    }

    /** Called first in `onNewIntent`, with its argument. `null` would mean: ignore this delivery. */
    fun onNewIntent(activity: Activity, intent: Intent): Incoming? =
        Incoming(intent) { name -> intent.data?.getQueryParameter(name) }
}
