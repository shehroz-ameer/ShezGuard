package com.shezguard.core.eval

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Parcel
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.Field
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.UriComponent
import com.shezguard.core.ViolationCode.URI_PARSER_MISMATCH
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config

/**
 * `docs/CANONICALISER_TESTS.md`, "Input contract": a hand-written `HierarchicalUri` parcel
 * whose encoded and decoded path disagree.
 *
 * Up to API 29, `Uri.Part.readFrom` and `PathPart.readFrom` accept representation `BOTH`
 * (0), followed by the encoded and then the decoded string, with no consistency check
 * (AOSP source, verified for android-7.0.0_r1 through android-security-10.0.0_r75;
 * `docs/PAPER_NOTES.md` N4). `toString()`, and therefore `Intent.getDataString()`, uses
 * the encoded form; `getPath()` returns the decoded one. From API 30 the format holds one
 * representation per part, and from API 34 the URI is re-parsed from a single string, so
 * these bytes cannot produce the mismatch there. The test therefore runs on SDK 29 only.
 *
 * Step 14: shared with the instrumented tests (`src/sharedTest`). On an emulator it runs at the
 * emulator's level and is skipped above API 29; what API 30+ does with these bytes, and whether the
 * object survives delivery to another app, is in `device/CraftedUriDeviceTest`.
 */
@RunWith(AndroidJUnit4::class)
@Config(sdk = [29])
class CraftedUriParcelTest {

    @Before
    fun onlyWhereTheFormatExists() {
        assumeTrue("representation BOTH is read only up to API 29", Build.VERSION.SDK_INT <= 29)
    }

    private fun craft(encodedPath: String, decodedPath: String): Uri = CraftedUri.craft(encodedPath, decodedPath)

    @Test
    fun blocksCraftedParcelWhoseDecodedPathDisagreesWithEncoded() {
        val uri = craft(encodedPath = "/product/1", decodedPath = "/admin/../../secret")
        // What the crafted object looks like to an app (printed for docs/PAPER_NOTES.md N4).
        println(
            "[N4] sdk=${Build.VERSION.SDK_INT} toString=<$uri> getPath=<${uri.path}> getEncodedPath=<${uri.encodedPath}> " +
                "getPathSegments=${uri.pathSegments}",
        )
        assertEquals("https://example.com/product/1?id=1", uri.toString())
        assertEquals("/admin/../../secret", uri.path)

        val d = ShezGuard.evaluate(Intent(Intent.ACTION_VIEW, uri), EvalFixtures.policy, "product")
        assertEquals(Outcome.BLOCK, d.outcome)
        assertTrue(d.violations.toString(), d.violations.any { it.code == URI_PARSER_MISMATCH && it.field == Field.UriPart(UriComponent.PATH) })
    }

    @Test
    fun consistentCraftedParcelIsAllowed() {
        val uri = craft(encodedPath = "/product/1", decodedPath = "/product/1")
        val d = ShezGuard.evaluate(Intent(Intent.ACTION_VIEW, uri), EvalFixtures.policy, "product")
        assertEquals(d.toString(), Outcome.ALLOW, d.outcome)
    }
}

/** The hand-written parcel, shared with `device/CraftedUriDeviceTest` (and the same bytes as `:attacker`'s `uri_mismatch`). */
internal object CraftedUri {
    private val hierarchicalTypeId = 3
    private val both = 0
    private val encodedOnly = 1

    fun craft(encodedPath: String, decodedPath: String): Uri {
        val p = Parcel.obtain()
        try {
            p.writeInt(hierarchicalTypeId)
            p.writeString("https")
            p.writeInt(both); p.writeString("example.com"); p.writeString("example.com") // authority
            p.writeInt(both); p.writeString(encodedPath); p.writeString(decodedPath)     // path
            p.writeInt(both); p.writeString("id=1"); p.writeString("id=1")               // query
            p.writeInt(encodedOnly); p.writeString(null)                                  // fragment: none
            p.setDataPosition(0)
            return Uri.CREATOR.createFromParcel(p)
        } finally {
            p.recycle()
        }
    }
}
