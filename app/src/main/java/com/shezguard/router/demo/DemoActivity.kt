package com.shezguard.router.demo

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.shezguard.router.guard.EntryGuard
import com.shezguard.router.guard.Incoming

/**
 * Base class of every demo entry point. It applies the step 10 call pattern in one place:
 * [EntryGuard] runs first, before `super.onCreate` / `super.onNewIntent`, and a `null` result
 * stops the delivery. In the vulnerable flavor the guard never returns `null`.
 *
 * RULE (step 11, author condition 1): subclasses read data and extras ONLY through the [Incoming]
 * passed to [handle] (`incoming.param(...)`, `incoming.intent.getXxxExtra(...)`). They never call
 * `getIntent()` / `intent` themselves.
 *
 * Each subclass logs what it did under [FakeData.TAG] ("ShezDemo"); the attack scripts read that log.
 * Logging raw values is deliberate here: this is the vulnerable demo app, not the library.
 */
abstract class DemoActivity : AppCompatActivity() {

    private lateinit var output: TextView

    final override fun onCreate(savedInstanceState: Bundle?) {
        val incoming = EntryGuard.onCreate(this)
        super.onCreate(incoming?.let { savedInstanceState })
        if (incoming == null) return
        output = TextView(this).apply { setPadding(32, 32, 32, 32); setTextIsSelectable(true) }
        setContentView(ScrollView(this).apply { addView(output) })
        handle(incoming)
    }

    final override fun onNewIntent(intent: Intent) {
        val incoming = EntryGuard.onNewIntent(this, intent) ?: return
        super.onNewIntent(incoming.intent)
        handle(incoming)
    }

    /** The entry point's own logic. Reads input only from [incoming]. */
    protected abstract fun handle(incoming: Incoming)

    /** Shows [message] on screen and logs it under "ShezDemo". */
    protected fun show(message: String) {
        Log.i(FakeData.TAG, "${javaClass.simpleName}: $message")
        output.append(message + "\n")
    }
}
