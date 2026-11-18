package com.shezguard.core.hardening

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Parcel
import com.shezguard.core.Decision
import com.shezguard.core.Outcome
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.hardening.Hardening.roundTrip
import com.shezguard.core.hardening.Hardening.view
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Step 15, area 1: can the app see something different from what ShezGuard checked? (Robolectric.)
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ValidatedVsUsedHardeningTest {

    private val policy = intentPolicy {
        entryPoint("any") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
            extras {
                allow("k", ExtraType.STRING)
                allow("n", ExtraType.INT)
                allow("arr", ExtraType.STRING_ARRAY)
            }
        }
        entryPoint("drop") {
            allowSchemes("https")
            allowHosts("example.com")
            anyPath()
            param("q") { string(CharClass.TEXT) }
            unknownParams(Unknown.Drop)
        }
        entryPoint("product") {
            allowSchemes("https")
            allowHosts("example.com")
            path { prefix("/product/") }
        }
    }

    // H2 (allowedIntentUriGetPathMustAgreeWithCheckedPath) moved in step 16 to
    // src/sharedTest/.../eval/PathAccessorAgreementTest.kt, after the fix.

    // ---- outside the stated scope (L26): recorded, passing ----------------------------------------------

    @Test
    fun observesSelectorOfAnAllowedIntentIsNeverChecked() {
        val i = view("https://example.com/x")
        i.selector = Intent(Intent.ACTION_VIEW, Uri.parse("https://evil.example/../admin?javascript:x"))
        val d = ShezGuard.evaluate(roundTrip(i), policy, "any")
        assertEquals(Outcome.ALLOW, d.outcome)
        assertEquals("evil.example", (d as Decision.Allow).intent.selector!!.data!!.host)
    }

    @Test
    fun observesClipDataUriWithGrantFlagsSurvivesAllow() {
        val i = view("https://example.com/x")
        i.clipData = ClipData.newRawUri("", Uri.parse("content://com.victim.provider/secrets"))
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        val d = ShezGuard.evaluate(roundTrip(i), policy, "any") as Decision.Allow
        assertEquals("content://com.victim.provider/secrets", d.intent.clipData!!.getItemAt(0).uri.toString())
        assertTrue(d.intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
    }

    @Test
    fun observesSanitizedCopyKeepsSelectorClipDataAndGrantFlags() {
        val i = view("https://example.com/x?q=a&utm=1")
        i.selector = Intent(Intent.ACTION_VIEW, Uri.parse("https://evil.example/"))
        i.clipData = ClipData.newRawUri("", Uri.parse("content://com.victim.provider/secrets"))
        i.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        val d = ShezGuard.evaluate(roundTrip(i), policy, "drop")
        assertEquals(Outcome.SANITIZE, d.outcome)
        val s = (d as Decision.Sanitize).sanitizedIntent
        assertNotNull(s.selector)
        assertNotNull(s.clipData)
        assertTrue(s.flags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION != 0)
    }

    /** In-process mutation is outside the threat model (malware inside the app); the decision is no snapshot. */
    @Test
    fun observesAllowReturnsTheSameMutableIntentObject() {
        val i = view("https://example.com/x").putExtra("k", "checked")
        val d = ShezGuard.evaluate(i, policy, "any") as Decision.Allow
        assertSame(i, d.intent)
        i.putExtra("k", "changed after the check").data = Uri.parse("https://evil.example/")
        assertEquals("example.com", d.data!!.host) // the GuardedUri is a snapshot
        assertEquals("evil.example", d.intent.data!!.host) // the intent is not
    }

    // ---- negative results ----------------------------------------------------------------------------------

    /** API 33+ lazy extras: ShezGuard reads a copy, the app reads the original; both come from the same bytes. */
    @Test
    @Config(sdk = [29, 34])
    fun holdsAppReadsTheSameExtrasShezGuardCheckedAfterIpc() {
        val sent = view("https://example.com/x").putExtra("k", "v").putExtra("n", 7).putExtra("arr", arrayOf("a", "b"))
        val received = roundTrip(sent)
        val d = ShezGuard.evaluate(received, policy, "any")
        assertEquals("sdk=${Build.VERSION.SDK_INT}", Outcome.ALLOW, d.outcome)
        assertEquals("v", received.getStringExtra("k"))
        assertEquals(7, received.getIntExtra("n", 0))
        assertArrayEquals(arrayOf("a", "b"), received.getStringArrayExtra("arr"))
    }

    /** A crafted OpaqueUri whose `toString()` reads as a hierarchical https URI (API <= 29 format). */
    @Test
    @Config(sdk = [29])
    fun holdsCraftedOpaqueUriThatPrintsAsHierarchical() {
        val p = Parcel.obtain()
        val uri = try {
            p.writeInt(2) // OpaqueUri.TYPE_ID
            p.writeString("https")
            p.writeInt(0); p.writeString("//example.com/product/1"); p.writeString("//example.com/product/1") // ssp, BOTH
            p.writeInt(1); p.writeString(null) // fragment: none
            p.setDataPosition(0)
            Uri.CREATOR.createFromParcel(p)
        } finally {
            p.recycle()
        }
        assertEquals("https://example.com/product/1", uri.toString())
        assertFalse(uri.isHierarchical)
        val d = ShezGuard.evaluate(Intent(Intent.ACTION_VIEW, uri), policy, "product")
        assertEquals(Outcome.BLOCK, d.outcome)
        assertTrue(d.violations.toString(), Hardening.codes(d).contains(ViolationCode.URI_PARSER_MISMATCH))
    }
}
