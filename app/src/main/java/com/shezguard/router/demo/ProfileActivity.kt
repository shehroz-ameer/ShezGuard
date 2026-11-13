package com.shezguard.router.demo

import com.shezguard.core.GuardedEntryPoint
import com.shezguard.router.guard.Incoming

/** Threat 5 (malformed Bundles): shows a "profile" object passed as a Serializable extra. */
@GuardedEntryPoint("profile")
class ProfileActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        // VULNERABLE (threat 5): deserialises whatever the caller sent, without try/catch. An unknown
        // class crashes the app (ClassNotFoundException inside the unparcel), and a LegacyProfile runs
        // its readObject side effect (threat 5b).
        @Suppress("DEPRECATION")
        val profile = incoming.intent.getSerializableExtra("profile")
        show("profile=${profile ?: "none"}")
    }
}
