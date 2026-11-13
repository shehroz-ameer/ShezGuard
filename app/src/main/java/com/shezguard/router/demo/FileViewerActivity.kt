package com.shezguard.router.demo

import com.shezguard.core.GuardedEntryPoint
import com.shezguard.router.guard.Incoming

/** Threat 2 (path traversal): https://shezguard.example/file?name=readme.txt shows a public help file. */
@GuardedEntryPoint("file")
class FileViewerActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        val name = incoming.param("name") ?: return show("no file name")
        // VULNERABLE (threat 2): the path is built from the parameter; name=../secret.txt escapes public/.
        val text = runCatching { FakeData.readRelative(this, "public/$name") }.getOrElse { "cannot read: ${it.javaClass.simpleName}" }
        show("file content: $text")
    }
}
