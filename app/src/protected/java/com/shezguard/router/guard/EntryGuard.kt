package com.shezguard.router.guard

import android.app.Activity
import android.content.Intent
import com.shezguard.core.ActivityGuard
import com.shezguard.core.CheckedIntent

/**
 * Flavor shim, protected version (step 12). The only flavor-specific behaviour; every sink is shared.
 *
 * Runs ShezGuard's [ActivityGuard] with the app-level [DemoPolicy] (not injected; the guard must exist
 * before `super.onCreate`, L34). On Block it returns `null` and the shared DemoActivity stops. Otherwise
 * the activity gets the checked intent (the sanitized copy on Sanitize), and URI parameters are read
 * only from the decision's `GuardedUri`, never with `getQueryParameter` on the raw intent (L11).
 */
object EntryGuard {
    private val guard by lazy { ActivityGuard(DemoPolicy.policy) }

    /** Called first in `onCreate`, before `super.onCreate`. `null` means: blocked, stop. */
    fun onCreate(activity: Activity): Incoming? = guard.onCreate(activity)?.toIncoming()

    /** Called first in `onNewIntent`, with its argument. `null` means: blocked, ignore this delivery. */
    fun onNewIntent(activity: Activity, intent: Intent): Incoming? = guard.onNewIntent(activity, intent)?.toIncoming()

    private fun CheckedIntent.toIncoming(): Incoming = Incoming(intent) { name -> data?.param(name) }
}
