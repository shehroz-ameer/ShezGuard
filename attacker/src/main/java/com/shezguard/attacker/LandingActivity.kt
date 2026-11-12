package com.shezguard.attacker

import android.app.Activity
import android.os.Bundle
import android.util.Log

/** Threat 3: the page the open redirect sends the user to. */
class LandingActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.w(AttackActivity.TAG, "CANARY-REDIRECT-LANDED on ${intent.data?.host} (the user is now on the attacker's page)")
        finish()
    }
}
