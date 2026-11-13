package com.shezguard.core.eval

import android.content.Intent
import android.os.Parcel
import org.junit.Assert.assertTrue
import java.io.ObjectInputStream
import java.io.Serializable

/**
 * Serializable payloads for threat 5 tests (step 12): an unknown class (t5) and a deserialisation
 * gadget (5b), matching the demo app's `t5_malformed_bundle.sh`. Used by [SerializableExtrasTest] and
 * by the IntentSanitizer baseline (`comparison/IntentSanitizerBaselineTest`).
 */
internal object SerialFixtures {
    /** Same length as [KnownPayloadA]'s name; no such class exists. */
    const val UNKNOWN_NAME = "com.shezguard.core.eval.KnownPayloadQ"

    /**
     * Parcels [sent], replaces [KnownPayloadA]'s class name with [UNKNOWN_NAME] in the raw bytes, and reads
     * the intent back (extras still parcelled), as when another app sends one of its own classes.
     */
    fun withUnknownClass(sent: Intent): Intent {
        val known = KnownPayloadA::class.java.name
        require(known.length == UNKNOWN_NAME.length)
        val bytes = Parcel.obtain().run {
            try {
                sent.writeToParcel(this, 0)
                marshall()
            } finally {
                recycle()
            }
        }
        // The Parcel stores the class name as UTF-16; the Java serialization stream inside it stores it as
        // (modified) UTF-8. Patch every occurrence of both.
        var replaced = 0
        for (charset in listOf(Charsets.UTF_16LE, Charsets.UTF_8)) {
            replaced += replaceAll(bytes, known.toByteArray(charset), UNKNOWN_NAME.toByteArray(charset))
        }
        assertTrue("class name found in the parcel bytes ($replaced replacements)", replaced >= 2)
        val p = Parcel.obtain()
        try {
            p.unmarshall(bytes, 0, bytes.size)
            p.setDataPosition(0)
            return Intent.CREATOR.createFromParcel(p)
        } finally {
            p.recycle()
        }
    }

    private fun replaceAll(haystack: ByteArray, from: ByteArray, to: ByteArray): Int {
        var n = 0
        var i = 0
        while (i <= haystack.size - from.size) {
            if (from.indices.all { haystack[i + it] == from[it] }) {
                to.copyInto(haystack, i)
                n++
                i += from.size
            } else {
                i++
            }
        }
        return n
    }
}

/** A plain Serializable that [SerialFixtures.withUnknownClass] turns into an unknown class name. */
internal class KnownPayloadA(val value: String) : Serializable {
    private companion object {
        private const val serialVersionUID: Long = 1L
    }
}

/** Like the demo app's LegacyProfile: `readObject` has a side effect (here, a counter). */
internal class GadgetPayload(val name: String) : Serializable {
    private fun readObject(input: ObjectInputStream) {
        input.defaultReadObject()
        readObjectCalls++
    }

    companion object {
        private const val serialVersionUID: Long = 1L

        @Volatile
        @JvmStatic
        var readObjectCalls: Int = 0
    }
}
