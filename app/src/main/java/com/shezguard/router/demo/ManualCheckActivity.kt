package com.shezguard.router.demo

import com.shezguard.core.GuardedEntryPoint
import com.shezguard.router.guard.Incoming
import java.net.URLDecoder

/**
 * Threat 6 (encoding evasion), and the "manual validation" baseline of docs/SPEC.md section 10.3:
 * the same file feature as FileViewerActivity, protected by a typical hand-written denylist.
 */
@GuardedEntryPoint("manual")
class ManualCheckActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        // VULNERABLE (threat 6): the check looks at the RAW link for a literal "..", but the value used
        // is decoded (once by getQueryParameter, and once more below). %2e%2e%2f and %252e%252e%252f
        // pass the check and become ../ .
        val raw = incoming.intent.dataString ?: ""
        if (raw.contains("..")) return show("rejected by the manual check")
        val name = URLDecoder.decode(incoming.param("name") ?: return show("no file name"), "UTF-8")
        val text = runCatching { FakeData.readRelative(this, "public/$name") }.getOrElse { "cannot read: ${it.javaClass.simpleName}" }
        show("file content: $text")
    }
}
