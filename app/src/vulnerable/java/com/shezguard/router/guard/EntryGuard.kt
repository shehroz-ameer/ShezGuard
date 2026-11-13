package com.shezguard.router.guard

import android.app.Activity
import android.content.Intent

/**
 * Flavor shim (step 11). This is the ONLY flavor-specific source file; every sink is shared.
 *
 * Pass-through: no check at all, and parameters are read the naive way, with
 * `Uri.getQueryParameter` on the raw intent. Never returns `null` (never blocks).
 * The library is on this flavor's classpath and the shared activities carry `@GuardedEntryPoint`, but
 * this flavor never calls it. The `protected` copy runs `ShezGuard`'s `ActivityGuard` (step 12).
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
