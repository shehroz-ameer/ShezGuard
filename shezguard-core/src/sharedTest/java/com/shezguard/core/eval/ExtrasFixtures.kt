package com.shezguard.core.eval

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Parcel
import android.os.Parcelable
import androidx.core.content.IntentSanitizer
import androidx.core.util.Predicate
import com.shezguard.core.android.NestedIntentSanitizer
import com.shezguard.core.policy.CharClass
import com.shezguard.core.policy.ExtraType
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.Nested
import com.shezguard.core.policy.Unknown
import com.shezguard.core.policy.intentPolicy

/**
 * Policies and helpers for the step 6 Robolectric tests. Separate from [EvalFixtures] because
 * building an `IntentSanitizer` needs Android classes, and some [EvalFixtures] users run on the
 * plain JVM.
 */
internal object ExtrasFixtures {

    val target = ComponentName("com.shezguard.test", "com.shezguard.test.Target")

    /** Counts how often the sanitizer's `note` predicate ran (condition 5: proof the sanitizer produced the output). */
    @Volatile
    var notePredicateCalls = 0

    private fun strict(): IntentSanitizer = IntentSanitizer.Builder()
        .allowComponent(target)
        .allowAction(Intent.ACTION_VIEW)
        .allowExtra("note", Predicate<Any> { notePredicateCalls++; it is String })
        .allowExtra("inner", Intent::class.java)
        .allowExtra("explode", Predicate<Any> { throw IllegalStateException("predicate failed") })
        .build()

    private fun anyComponent(): IntentSanitizer = IntentSanitizer.Builder()
        .allowAnyComponent()
        .allowAction(Intent.ACTION_VIEW)
        .build()

    /** Built lazily, under Robolectric. */
    val policy: IntentPolicy by lazy {
        intentPolicy {
            entryPoint("share") {
                extras {
                    allow("title", ExtraType.STRING)
                    allow("count", ExtraType.INT)
                    allow("on", ExtraType.BOOLEAN)
                    allow("tags", ExtraType.STRING_ARRAY)
                    allow("ids", ExtraType.LONG_ARRAY)
                }
            }
            entryPoint("forward") {
                extras { allow("title", ExtraType.STRING) }
                nestedIntents(Nested.AllowSanitized(setOf("next"), NestedIntentSanitizer(strict())))
            }
            entryPoint("forwardAny") {
                nestedIntents(Nested.AllowSanitized(setOf("next"), NestedIntentSanitizer(anyComponent())))
            }
            entryPoint("searchExtras") {
                allowSchemes("https")
                allowHosts("example.com")
                path { exact("/search") }
                param("q") { string(CharClass.TEXT) }
                unknownParams(Unknown.Drop)
                extras { allow("title", ExtraType.STRING) }
            }
        }
    }

    /**
     * An intent as an Activity receives it: written to a Parcel, read back (extras still parcelled), and
     * given the app's class loader for its extras, as `ActivityThread.performLaunchActivity` and
     * `deliverNewIntents` do before the app sees it (`setExtrasClassLoader(cl)`; AOSP tags
     * android-7.0.0_r36 line 2541 and android-security-14.0.0_r31 line 3679). Step 14: without the loader,
     * a device resolves app classes with the boot class loader (N8), so a hostile `CREATOR` never ran and
     * the extras tests passed on a "class not found" failure instead. Setting the loader does not
     * unparcel the extras. Under Robolectric one loader loads everything, so the JVM results are unchanged.
     */
    fun received(sent: Intent): Intent =
        receivedWithoutLoader(sent).apply { setExtrasClassLoader(ExtrasFixtures::class.java.classLoader) }

    /** Like [received] but with no extras class loader: only for tests that characterise that case (N8). */
    fun receivedWithoutLoader(sent: Intent): Intent {
        val p = Parcel.obtain()
        try {
            sent.writeToParcel(p, 0)
            p.setDataPosition(0)
            return Intent.CREATOR.createFromParcel(p)
        } finally {
            p.recycle()
        }
    }

    /** Hidden `BaseBundle.isParcelled()` of the intent's own extras (no copy), via reflection. */
    fun extrasParcelled(i: Intent): Boolean {
        val f = Intent::class.java.getDeclaredField("mExtras").apply { isAccessible = true }
        val bundle = f.get(i) as Bundle? ?: return false
        val m = Class.forName("android.os.BaseBundle").getDeclaredMethod("isParcelled").apply { isAccessible = true }
        return m.invoke(bundle) as Boolean
    }

    fun nestedBundles(levels: Int, leaf: Bundle.() -> Unit): Bundle {
        var b = Bundle().apply(leaf)
        repeat(levels - 1) { b = Bundle().apply { putBundle("b", b) } }
        return b
    }
}

/** A Parcelable whose CREATOR throws: a Bundle that throws on read (threat 5). */
class ThrowingParcelable : Parcelable {
    override fun describeContents(): Int = 0
    override fun writeToParcel(dest: Parcel, flags: Int) = dest.writeInt(42)

    companion object {
        @Volatile
        var created: Int = 0

        @JvmField
        val CREATOR: Parcelable.Creator<ThrowingParcelable> = object : Parcelable.Creator<ThrowingParcelable> {
            override fun createFromParcel(source: Parcel): ThrowingParcelable {
                created++
                throw IllegalStateException("hostile CREATOR")
            }

            override fun newArray(size: Int): Array<ThrowingParcelable?> = arrayOfNulls(size)
        }
    }
}

/** A Parcelable with no CREATOR: reading it fails with `BadParcelableException`. */
class NoCreatorParcelable : Parcelable {
    override fun describeContents(): Int = 0
    override fun writeToParcel(dest: Parcel, flags: Int) = dest.writeInt(1)
}

/** A harmless custom Parcelable, standing in for an app or library type. */
class PlainParcelable() : Parcelable {
    override fun describeContents(): Int = 0
    override fun writeToParcel(dest: Parcel, flags: Int) = dest.writeInt(7)

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<PlainParcelable> = object : Parcelable.Creator<PlainParcelable> {
            override fun createFromParcel(source: Parcel): PlainParcelable = PlainParcelable().also { source.readInt() }
            override fun newArray(size: Int): Array<PlainParcelable?> = arrayOfNulls(size)
        }
    }
}
