package com.shezguard.router.demo

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * Not exported (manifest): only this app can start it. Reaching it from another app proves intent
 * redirection (threat 1). Reads no input.
 */
class InternalAdminActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.w(FakeData.TAG, "InternalAdminActivity: $CANARY_ADMIN (non-exported admin screen opened)")
        setContentView(TextView(this).apply { text = "Internal admin screen (fake)" })
    }

    companion object {
        const val CANARY_ADMIN = "CANARY-ADMIN-REACHED"
    }
}
