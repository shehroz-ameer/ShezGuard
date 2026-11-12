package com.shezguard.router.demo

import android.content.Intent
import android.net.Uri
import com.shezguard.router.guard.Incoming

/** Threat 3 (open redirect): https://shezguard.example/redirect?next=... "continues to the next page". */
class RedirectActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        val next = incoming.param("next") ?: return show("no next page")
        show("continuing to the next page")
        // VULNERABLE (threat 3): any URL is opened on the app's behalf, e.g. https://attacker.invalid/.
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(next)))
        finish()
    }
}
