package com.shezguard.core.device

import android.content.Intent
import android.os.BadParcelableException
import android.os.Build
import android.os.Parcel
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.shezguard.core.ShezGuard
import com.shezguard.core.ViolationCode.EVALUATION_FAILED
import com.shezguard.core.eval.EvalFixtures.codes
import com.shezguard.core.eval.ExtrasFixtures
import com.shezguard.core.eval.ExtrasFixtures.received
import com.shezguard.core.eval.KnownPayloadA
import com.shezguard.core.eval.PlainParcelable
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * `docs/PAPER_NOTES.md` N8, device-only (step 14): a nested Intent's extras are read with
 * `Parcel.readBundle()` (null loader), so an app-defined Parcelable inside them is resolved with the
 * class loader of `Parcel` itself, not the app's. Robolectric cannot show this: one sandbox loader
 * loads both framework and test classes there.
 *
 * The outer intent gets the app's loader, as `ActivityThread` does before `onCreate` (AOSP source, see
 * `ExtrasFixtures.received`); the nested one gets nothing, because `Intent.readFromParcel` gives it none. Lines tagged `[N8]` are recorded for the docs.
 */
@RunWith(AndroidJUnit4::class)
@Suppress("DEPRECATION")
class NestedIntentClassLoaderTest {

    private val sdk = Build.VERSION.SDK_INT
    private val appLoader: ClassLoader = javaClass.classLoader!!

    private fun record(line: String) = println("[N8] sdk=$sdk $line")

    /** Outer intent as an Activity receives it: parcelled, read back, extras loader set to the app's. */
    private fun outerWithNested(nested: Intent): Intent =
        received(Intent().putExtra("title", "t").putExtra("next", nested)) // received() sets the app's loader on the outer intent

    private fun nestedOf(outer: Intent): Intent = outer.getParcelableExtra("next")!!

    @Test
    fun parcelClassLoaderIsNotTheAppLoader() {
        val parcelLoader = Parcel::class.java.classLoader
        record("Parcel.class loader=${parcelLoader?.javaClass?.name} app loader=${appLoader.javaClass.name}")
        assertNotSame(appLoader, parcelLoader)
    }

    @Test
    fun appParcelableInNestedIntentFailsToResolve() {
        val nested = nestedOf(outerWithNested(Intent(Intent.ACTION_VIEW).putExtra("note", "hi").putExtra("p", PlainParcelable())))
        val r = runCatching { nested.extras!!.get("p") }
        record(
            "nested app Parcelable, no loader on nested: " +
                (r.exceptionOrNull()?.let { "${it.javaClass.simpleName}: ${it.message?.take(120)}" } ?: "read ${r.getOrNull()?.javaClass?.name}"),
        )
        assertTrue("expected a resolution failure, got ${r.getOrNull()}", r.exceptionOrNull() is BadParcelableException)
    }

    /** Control: the same bytes resolve once the nested intent's loader is set, so the loader is the cause. */
    @Test
    fun appParcelableInNestedIntentResolvesWithAppLoader() {
        val nested = nestedOf(outerWithNested(Intent(Intent.ACTION_VIEW).putExtra("p", PlainParcelable())))
        nested.setExtrasClassLoader(appLoader)
        val v = nested.extras!!.get("p")
        record("nested app Parcelable, app loader set on nested: read ${v?.javaClass?.name}")
        assertTrue(v is PlainParcelable)
    }

    /** Characterisation only (N8 "not verified": Serializable resolution with a null loader on ART). */
    @Test
    fun characterisesAppSerializableInNestedIntent() {
        val nested = nestedOf(outerWithNested(Intent(Intent.ACTION_VIEW).putExtra("s", KnownPayloadA("x"))))
        val r = runCatching { nested.extras!!.get("s") }
        record(
            "nested app Serializable, no loader on nested: " +
                (r.exceptionOrNull()?.let { "${it.javaClass.simpleName}: ${it.message?.take(120)}" } ?: "read ${r.getOrNull()?.javaClass?.name}"),
        )
    }

    /**
     * What ShezGuard does with such a nested intent under `Nested.AllowSanitized` ("forward": the
     * sanitizer allows the component, VIEW and the "note" extra). Recorded, not asserted beyond "no
     * crash and no EVALUATION_FAILED": library behaviour is not changed in step 14.
     */
    @Test
    fun recordsShezGuardDecisionForUnresolvableNestedExtra() {
        val nested = Intent(Intent.ACTION_VIEW).setComponent(ExtrasFixtures.target).putExtra("note", "hi").putExtra("p", PlainParcelable())
        val d = ShezGuard.evaluate(outerWithNested(nested), ExtrasFixtures.policy, "forward")
        record("ShezGuard forward, nested app Parcelable: ${d.outcome} ${d.violations.map { "${it.code.id}@${it.field}" }}")
        assertFalse(EVALUATION_FAILED in codes(d))
    }
}
