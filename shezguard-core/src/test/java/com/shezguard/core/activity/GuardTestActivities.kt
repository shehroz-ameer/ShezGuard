package com.shezguard.core.activity

import android.app.Activity
import android.app.Fragment
import android.content.Intent
import android.os.Bundle
import com.shezguard.core.ActivityGuard
import com.shezguard.core.CheckedIntent
import com.shezguard.core.GuardedEntryPoint

/**
 * Test activities for step 10. Each uses the exact call pattern documented in the README:
 * the guard runs before `super.onCreate`, `null` is passed to `super.onCreate` on Block, and the
 * app returns early. [GuardHarness.guard] is set by each test before an activity is created
 * (test-only global state; the library itself holds none).
 */
internal object GuardHarness {
    lateinit var guard: ActivityGuard
}

open class HarnessActivity : Activity() {
    /** The last checked intent the app received, or `null` if every delivery was blocked. */
    var checked: CheckedIntent? = null

    /** Set only by app code that runs after the guard allowed the launch. */
    var appCodeRanInOnCreate: Boolean = false

    /** How many times app code after the guard ran in `onNewIntent`. */
    var newIntentBodyRuns: Int = 0

    /** The `savedInstanceState` that reached `super.onCreate`. */
    var stateGivenToSuper: Bundle? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        val checked = GuardHarness.guard.onCreate(this)
        stateGivenToSuper = checked?.let { savedInstanceState }
        super.onCreate(checked?.let { savedInstanceState })
        if (checked == null) return
        this.checked = checked
        appCodeRanInOnCreate = true
    }

    override fun onNewIntent(intent: Intent) {
        val checked = GuardHarness.guard.onNewIntent(this, intent) ?: return
        super.onNewIntent(checked.intent)
        this.checked = checked
        newIntentBodyRuns++
    }
}

@GuardedEntryPoint("product")
open class ProductActivity : HarnessActivity()

/** Not annotated itself: `@GuardedEntryPoint` is not inherited. */
class ProductSubclassActivity : ProductActivity()

@GuardedEntryPoint("plain")
class PlainActivity : HarnessActivity()

/**
 * Sets a result before the guard runs (in its initializer), so a test can tell whether a Block
 * actively resets it. A new Activity already starts with `RESULT_CANCELED` and no data, so without
 * this a missing `setResult` call in the guard would go unnoticed (step 10 mutant (e)).
 */
@GuardedEntryPoint("product")
class PresetResultActivity : HarnessActivity() {
    init {
        setResult(RESULT_OK, Intent().putExtra("preset", true))
    }
}

@GuardedEntryPoint("partner")
class PartnerActivity : HarnessActivity()

@GuardedEntryPoint("strict")
class StrictPartnerActivity : HarnessActivity()

class UnannotatedActivity : HarnessActivity()

@GuardedEntryPoint(exempt = true)
class ExemptActivity : HarnessActivity()

@GuardedEntryPoint("")
class EmptyNameActivity : HarnessActivity()

@GuardedEntryPoint("product", exempt = true)
class NamedButExemptActivity : HarnessActivity()

@GuardedEntryPoint("notInPolicy")
class UnregisteredActivity : HarnessActivity()

/**
 * A framework fragment that records how often the platform created it, and how often from saved
 * state. It saves a marker so that a restored instance always gets a non-null saved state.
 */
@Suppress("DEPRECATION")
class RecordingFragment : Fragment() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        created++
        if (savedInstanceState?.getBoolean("marker") == true) restoredFromState++
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean("marker", true)
    }

    companion object {
        @JvmStatic
        var created: Int = 0

        @JvmStatic
        var restoredFromState: Int = 0
    }
}
