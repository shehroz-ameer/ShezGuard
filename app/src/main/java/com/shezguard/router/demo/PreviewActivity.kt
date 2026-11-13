package com.shezguard.router.demo

import com.shezguard.core.GuardedEntryPoint
import android.annotation.SuppressLint
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import com.shezguard.router.guard.Incoming

/** Threat 2 (attacker URL in a WebView): https://shezguard.example/preview?url=... */
@GuardedEntryPoint("preview")
class PreviewActivity : DemoActivity() {
    @SuppressLint("SetJavaScriptEnabled")
    override fun handle(incoming: Incoming) {
        val url = incoming.param("url") ?: return show("no url")
        val web = WebView(this)
        // VULNERABLE (threat 2): JavaScript and file access on, and the page is caller-chosen, so
        // javascript:, data: and file:// URLs (for example the app's own files/secret.txt) are loaded.
        web.settings.javaScriptEnabled = true
        web.settings.allowFileAccess = true
        web.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(m: ConsoleMessage): Boolean {
                Log.i(FakeData.TAG, "PreviewActivity: console: ${m.message()}")
                return true
            }
        }
        web.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView, loaded: String) {
                // A "preview" feature that reports the page text; it shows what the page contained.
                view.evaluateJavascript("document.body ? document.body.innerText : ''") { text ->
                    Log.i(FakeData.TAG, "PreviewActivity: page text: ${text.take(200)}")
                }
            }
        }
        setContentView(web)
        show("loading the requested page")
        web.loadUrl(url)
    }
}
