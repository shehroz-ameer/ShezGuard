package com.shezguard.router.guard

import android.content.Intent
import android.net.Uri
import com.shezguard.core.Decision
import com.shezguard.core.GuardedEntryPoint
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode
import com.shezguard.core.ViolationCode.EXTRA_TOO_LARGE
import com.shezguard.core.ViolationCode.PARAM_URL_NOT_ALLOWED
import com.shezguard.core.ViolationCode.URI_DOUBLE_ENCODING
import com.shezguard.router.MainActivity
import com.shezguard.router.demo.FileViewerActivity
import com.shezguard.router.demo.ForwardActivity
import com.shezguard.router.demo.LinkActivity
import com.shezguard.router.demo.ManualCheckActivity
import com.shezguard.router.demo.NoteActivity
import com.shezguard.router.demo.PreviewActivity
import com.shezguard.router.demo.ProfileActivity
import com.shezguard.router.demo.RedirectActivity
import com.shezguard.router.demo.SearchActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The demo app's policy (step 12, protected flavor). Builds it (DSL checks run at build time, SPEC 7),
 * checks that annotations and policy match, and replays the URI and extras parts of the attacks and
 * benign controls through `ShezGuard.evaluate` on the JVM. The device evidence is in
 * docs/ATTACK_MATRIX.md; this test makes the policy-level part reproducible without an emulator.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DemoPolicyTest {

    private val guarded = listOf(
        ForwardActivity::class.java, SearchActivity::class.java, PreviewActivity::class.java, FileViewerActivity::class.java,
        NoteActivity::class.java, RedirectActivity::class.java, LinkActivity::class.java, ProfileActivity::class.java,
        ManualCheckActivity::class.java,
    )

    @Test
    fun everyGuardedActivityNamesAnEntryPointAndEveryEntryPointIsUsed() {
        val names = guarded.map { it.getAnnotation(GuardedEntryPoint::class.java)!!.also { a -> assertTrue(!a.exempt) }.name }
        assertEquals(names.toSet(), DemoPolicy.policy.entryPoints.keys)
        assertEquals("one activity per entry point", names.size, names.toSet().size)
        assertTrue(MainActivity::class.java.getAnnotation(GuardedEntryPoint::class.java)!!.exempt)
    }

    private fun view(uri: String) = Intent(Intent.ACTION_VIEW, Uri.parse(uri)).addCategory(Intent.CATEGORY_BROWSABLE)

    private fun decide(ep: String, intent: Intent) = ShezGuard.evaluate(intent, DemoPolicy.policy, ep)

    private fun codes(d: Decision): List<ViolationCode> = d.violations.map { it.code }

    private fun assertAllowed(ep: String, uri: String) {
        val d = decide(ep, view(uri))
        assertTrue("$uri: $d", d is Decision.Allow)
    }

    private fun assertBlocked(ep: String, uri: String, vararg expected: ViolationCode) {
        val d = decide(ep, view(uri))
        assertTrue("$uri: $d", d is Decision.Block)
        assertEquals(uri, expected.toList(), codes(d))
    }

    @Test
    fun benignLinksAreAllowed() {
        assertAllowed("search", "https://shezguard.example/search?q=blue%20mug")
        assertAllowed("preview", "https://shezguard.example/preview?url=https%3A%2F%2Fshezguard.example%2Fhelp")
        assertAllowed("file", "https://shezguard.example/file?name=readme.txt")
        assertAllowed("redirect", "https://shezguard.example/redirect?next=https%3A%2F%2Fshezguard.example%2Fhelp")
        assertAllowed("login", "https://shezguard.example/login?token=abc123")
        assertAllowed("login", "shezdemo://login?token=abc123")
        assertAllowed("manual", "https://shezguard.example/manual?name=readme.txt")
    }

    @Test
    fun blockedAttackLinksGiveTheCodesSeenOnTheDevice() {
        assertBlocked("preview", "https://shezguard.example/preview?url=file%3A%2F%2F%2Fdata%2Fuser%2F0%2Fcom.shezguard.router%2Ffiles%2Fsecret.txt", PARAM_URL_NOT_ALLOWED)
        assertBlocked("preview", "https://shezguard.example/preview?url=data%3Atext%2Fhtml%2C%3Cscript%3Econsole.log(%27CANARY-JS-%27%2B(6*7))%3C%2Fscript%3E", PARAM_URL_NOT_ALLOWED)
        assertBlocked("redirect", "https://shezguard.example/redirect?next=https%3A%2F%2Fattacker.invalid%2Flogin", PARAM_URL_NOT_ALLOWED)
        assertBlocked("manual", "https://shezguard.example/manual?name=%252e%252e%252fsecret.txt", URI_DOUBLE_ENCODING)
    }

    /** Not prevented by this policy (docs/ATTACK_MATRIX.md): the values are valid PRINTABLE_ASCII (L37). */
    @Test
    fun notPreventedAttackLinksAreAllowed() {
        assertAllowed("search", "https://shezguard.example/search?q=x%27%20OR%20hidden%3D1%20--")
        assertAllowed("file", "https://shezguard.example/file?name=../secret.txt")
        assertAllowed("manual", "https://shezguard.example/manual?name=../secret.txt")
        assertAllowed("manual", "https://shezguard.example/manual?name=%2e%2e%2fsecret.txt")
    }

    /** The scheme x host cross-product of the "login" entry point (L39): both mismatched pairs are allowed. */
    @Test
    fun loginAcceptsEverySchemeWithEveryHost() {
        assertAllowed("login", "shezdemo://shezguard.example/login?token=abc123")
        assertAllowed("login", "https://login?token=abc123")
    }

    @Test
    fun noteExtras() {
        val note = Intent().putExtra("note", "Buy milk").putExtra("copies", 2)
        assertTrue(decide("note", note) is Decision.Allow)
        val large = Intent().putExtra("note", "A".repeat(64_000)).putExtra("copies", 20_000)
        assertEquals(listOf(EXTRA_TOO_LARGE), codes(decide("note", large)))
        // L38: a huge int is not bounded.
        val copies = Intent().putExtra("note", "A".repeat(1000)).putExtra("copies", 2_000_000)
        assertTrue(decide("note", copies) is Decision.Allow)
    }
}
