package com.shezguard.router.demo

import com.shezguard.router.guard.Incoming

/**
 * Threat 4 (hijackable deep links): shezdemo://login?token=... and https://shezguard.example/login?token=...
 * The vulnerability is in the manifest (a custom scheme, and https without autoVerify): another app can
 * declare the same filters and receive the token instead of this app. Nothing in this code can prevent it.
 */
class LinkActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        val token = incoming.param("token")
        show(if (token.isNullOrEmpty()) "no login token" else "signed in with a one-time token")
    }
}
