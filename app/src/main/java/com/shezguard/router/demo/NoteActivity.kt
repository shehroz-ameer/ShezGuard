package com.shezguard.router.demo

import com.shezguard.core.GuardedEntryPoint
import com.shezguard.router.guard.Incoming

/** Threat 2 (oversized values): shows a "note" extra repeated "copies" times. */
@GuardedEntryPoint("note")
class NoteActivity : DemoActivity() {
    override fun handle(incoming: Incoming) {
        val note = incoming.intent.getStringExtra("note") ?: ""
        val copies = incoming.intent.getIntExtra("copies", 1)
        // VULNERABLE (threat 2): no limit on either extra. A large note times a large count exhausts the
        // heap (OutOfMemoryError): the app crashes, a denial of service.
        val preview = note.repeat(copies)
        show("note length=${note.length} copies=$copies preview length=${preview.length}")
    }
}
