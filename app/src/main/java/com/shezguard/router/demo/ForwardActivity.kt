package com.shezguard.router.demo

import com.shezguard.core.GuardedEntryPoint
import android.content.Intent
import com.shezguard.router.guard.Incoming

/** Threat 1 (intent redirection): "forwards the user to the next screen". */
@GuardedEntryPoint("forward")
class ForwardActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        @Suppress("DEPRECATION")
        val next = incoming.intent.getParcelableExtra<Intent>("next")
        if (next == null) {
            show("no next screen")
            return
        }
        show("forwarding to ${next.component?.flattenToShortString() ?: next.action}")
        // VULNERABLE (threat 1): launches a caller-supplied Intent with this app's identity, so a caller
        // reaches components it could never start itself, such as the non-exported InternalAdminActivity.
        startActivity(next)
    }
}
