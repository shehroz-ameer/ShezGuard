package com.shezguard.core.hardening

import android.content.Intent
import android.net.Uri
import android.os.Parcel
import com.shezguard.core.Decision
import com.shezguard.core.ViolationCode
import java.io.File

/**
 * Step 15 hardening review helpers (docs/HARDENING.md).
 *
 * Conventions in this package:
 * - a test named `blocks...` / `...MustAgree` etc. asserts a protection ShezGuard claims. If it FAILS, it
 *   demonstrates a finding (an H-number in docs/HARDENING.md);
 * - a test named `observes...` asserts the current, unsafe-looking behaviour of something OUTSIDE the stated
 *   scope (already listed in docs/LIMITATIONS.md); it passes and serves as evidence;
 * - a test named `holds...` is a negative result: an attack that was tried and is stopped.
 */
internal object Hardening {
    private val outDir = File(System.getProperty("shezguard.hardening.out") ?: "build/hardening")

    /** Writes a report file under build/hardening (numbers and fuzz samples quoted in docs/HARDENING.md). */
    fun report(name: String, text: String) {
        outDir.mkdirs()
        File(outDir, name).writeText(text)
        println("[hardening] wrote ${File(outDir, name)}")
    }

    fun view(uri: String): Intent = Intent(Intent.ACTION_VIEW, Uri.parse(uri))

    /** Marshals and unmarshals the intent, as binder IPC does; the extras come back parcelled (lazy). */
    fun roundTrip(intent: Intent): Intent {
        val p = Parcel.obtain()
        try {
            intent.writeToParcel(p, 0)
            p.setDataPosition(0)
            return Intent.CREATOR.createFromParcel(p)
        } finally {
            p.recycle()
        }
    }

    /** See ResourceExhaustionHardeningTest.on8Mb. */
    fun on8MbQuiet(block: () -> Unit): Throwable? {
        val out = System.out
        val err = System.err
        val sink = java.io.PrintStream(java.io.OutputStream.nullOutputStream())
        var thrown: Throwable? = null
        try {
            System.setOut(sink); System.setErr(sink)
            val t = Thread(null, { try { block() } catch (e: Throwable) { thrown = e } }, "main-like", 8L shl 20)
            t.start(); t.join()
        } finally {
            System.setOut(out); System.setErr(err)
        }
        return thrown
    }

    fun codes(d: Decision): Set<ViolationCode> = d.violations.map { it.code }.toSet()
}
