package com.shezguard.router.demo

import java.io.Serializable

/**
 * Same fully qualified name, field and serialVersionUID as the demo app's LegacyProfile, so the demo
 * app deserialises it as its own class and runs its own readObject (threat 5b). No logic here.
 */
class LegacyProfile(val name: String) : Serializable {
    private companion object {
        private const val serialVersionUID: Long = 1L
    }
}
