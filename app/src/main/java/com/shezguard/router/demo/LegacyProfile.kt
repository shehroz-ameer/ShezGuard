package com.shezguard.router.demo

import android.util.Log
import java.io.File
import java.io.ObjectInputStream
import java.io.Serializable

/**
 * A Serializable kept for "backward compatibility" (threat 5b). Its readObject has a side effect,
 * which is all a deserialisation gadget needs: whoever deserialises an attacker's instance runs it.
 */
class LegacyProfile(val name: String) : Serializable {

    // VULNERABLE (threat 5): side effect during deserialisation. It runs inside whatever code unparcels
    // the extra, before any check on the value can happen.
    private fun readObject(input: ObjectInputStream) {
        input.defaultReadObject()
        val marker = File(appFilesDir ?: return, "gadget-ran.txt")
        marker.writeText("legacy profile migrated\n")
        Log.w(FakeData.TAG, "LegacyProfile: CANARY-GADGET-${marker.length()} side effect ran during deserialisation")
    }

    override fun toString(): String = "LegacyProfile(name=$name)"

    companion object {
        private const val serialVersionUID: Long = 1L

        /** Set by DemoApp.onCreate; a static so readObject can find the app's files directory. */
        @JvmStatic
        var appFilesDir: File? = null
    }
}
