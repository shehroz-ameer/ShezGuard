package com.shezguard.core.device.probe

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Bundle
import com.shezguard.core.Decision
import com.shezguard.core.Delivery
import com.shezguard.core.ShezGuard
import com.shezguard.core.eval.EvalFixtures
import com.shezguard.core.eval.ExtrasFixtures
import com.shezguard.core.policy.IntentPolicy
import com.shezguard.core.policy.intentPolicy
import java.security.MessageDigest
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Step 14 phase 2 (emulator only): activities in the instrumented test APK that another app
 * (`:attacker`'s `IdentityActivity`) launches. Each records what the platform reports and what
 * ShezGuard decides, in a fixed order, then finishes. The test runs in the same process and reads
 * the records from [ProbeLog].
 *
 * Order inside [record] matters: ShezGuard runs first; then the raw platform values; and
 * `Activity.getReferrer()` last, because it unparcels the caller's extras (N11).
 */
internal object Probe {
    const val SELF = "com.shezguard.core.test"
    const val ATTACKER = "com.shezguard.attacker"
    const val ROUTER = "com.shezguard.router"

    /**
     * SHA-256 of this test APK's own signing certificate, read from the installed package at run
     * time (no keystore is read). `:attacker` is built on the same machine with the same debug
     * certificate, so the same digest lists it; the for-result test fails if that assumption is wrong.
     * Never printed.
     */
    @Suppress("DEPRECATION")
    fun selfDigest(context: Context): String {
        val pm = context.packageManager
        val signers: Array<Signature> = if (Build.VERSION.SDK_INT >= 28) {
            pm.getPackageInfo(SELF, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo!!.apkContentsSigners
        } else {
            pm.getPackageInfo(SELF, PackageManager.GET_SIGNATURES).signatures!!
        }
        check(signers.size == 1) { "expected one signer" }
        return MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray()).joinToString("") { "%02x".format(it) }
    }

    @Volatile
    private var cached: IntentPolicy? = null

    /** Caller entry points (no data, no extras rules). */
    fun policy(context: Context): IntentPolicy = cached ?: run {
        val d = selfDigest(context)
        intentPolicy {
            entryPoint("partner") { allowedPackages { pkg(ATTACKER, d) } }
            entryPoint("strict") { allowedPackages(requireReliableIdentity = true) { pkg(ATTACKER, d) } }
            entryPoint("wrongKey") { allowedPackages { pkg(ATTACKER, "0".repeat(64)) } }
            entryPoint("self") { allowedPackages { pkg(SELF, d) } }
            entryPoint("router") { allowedPackages { pkg(ROUTER, d) } }
        }.also { cached = it }
    }

    val callerEntryPoints = listOf("partner", "strict", "wrongKey", "self", "router")

    private fun parcelled(i: Intent?): Boolean? = try {
        if (i == null) null else ExtrasFixtures.extrasParcelled(i)
    } catch (e: Exception) {
        null // reflection blocked (hidden_api_policy not set)
    }

    fun record(activity: Activity, intent: Intent, delivery: Delivery) {
        val before = parcelled(intent)
        val policy = policy(activity)
        val decisions = LinkedHashMap<String, Decision>()
        for (ep in callerEntryPoints) decisions[ep] = ShezGuard.evaluate(activity, intent, delivery, policy, ep)
        // Misuse, for contrast only: an onNewIntent intent evaluated as if it were the launch.
        if (delivery == Delivery.NEW_INTENT) {
            decisions["self(asLaunch)"] = ShezGuard.evaluate(activity, intent, Delivery.LAUNCH, policy, "self")
        }
        if (intent.data != null) {
            decisions["product"] = ShezGuard.evaluate(activity, intent, delivery, EvalFixtures.policy, "product")
        }
        val afterGuard = parcelled(intent)
        // N8: the class loader ActivityThread gave the delivered intent's extras. getExtras() returns a copy
        // that carries the loader (Bundle copy constructor) without unparcelling (N7 point 1).
        val extrasLoader = intent.extras?.let { b ->
            val cl = b.classLoader
            when {
                cl === activity.classLoader -> "app"
                cl == null -> "null"
                else -> cl.javaClass.simpleName
            }
        } ?: "no-extras"
        val activityIntentAfterGuard = parcelled(activity.intent)
        val calling = activity.callingPackage
        val launchedFrom = if (Build.VERSION.SDK_INT >= 34) activity.launchedFromPackage else null
        val attackerVisible = try {
            activity.packageManager.getPackageInfo(ATTACKER, 0); true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
        val data = intent.data
        // Last: getReferrer() reads EXTRA_REFERRER with getParcelableExtra on getIntent() (N11).
        val referrer = activity.referrer?.toString()
        val afterReferrer = parcelled(activity.intent)
        ProbeLog.records.add(
            ProbeRecord(
                activity = activity.javaClass.simpleName,
                extrasLoader = extrasLoader,
                delivery = delivery,
                callingPackage = calling,
                launchedFromPackage = launchedFrom,
                attackerVisible = attackerVisible,
                referrer = referrer,
                extrasParcelledBefore = before,
                extrasParcelledAfterGuard = afterGuard,
                activityIntentParcelledAfterGuard = activityIntentAfterGuard,
                activityIntentParcelledAfterGetReferrer = afterReferrer,
                dataString = intent.dataString,
                path = data?.path,
                encodedPath = data?.encodedPath,
                pathSegments = data?.pathSegments,
                decisions = decisions,
            ),
        )
    }
}

internal data class ProbeRecord(
    val activity: String,
    /** "app" if the delivered intent's extras carry the activity's class loader, else its class or "null"; "no-extras". */
    val extrasLoader: String,
    val delivery: Delivery,
    val callingPackage: String?,
    /** API 34+ only; `null` below. */
    val launchedFromPackage: String?,
    /** Whether `getPackageInfo(attacker)` succeeded, read after ShezGuard ran. */
    val attackerVisible: Boolean,
    /** `Activity.getReferrer()`, read last. */
    val referrer: String?,
    /** `null`: no extras, or the reflection was blocked. */
    val extrasParcelledBefore: Boolean?,
    val extrasParcelledAfterGuard: Boolean?,
    val activityIntentParcelledAfterGuard: Boolean?,
    val activityIntentParcelledAfterGetReferrer: Boolean?,
    val dataString: String?,
    val path: String?,
    val encodedPath: String?,
    val pathSegments: List<String>?,
    val decisions: Map<String, Decision>,
) {
    fun summary(ep: String): String {
        val d = decisions.getValue(ep)
        return "${d.javaClass.simpleName.uppercase()}(${d.callerIdentitySource})${d.violations.map { it.code }}"
    }

    fun line(): String = buildString {
        append("activity=$activity delivery=$delivery extrasLoader=$extrasLoader calling=$callingPackage launchedFrom=$launchedFromPackage ")
        append("attackerVisible=$attackerVisible referrer=$referrer ")
        append("parcelled[before=$extrasParcelledBefore afterGuard=$extrasParcelledAfterGuard ")
        append("activityIntentAfterGuard=$activityIntentParcelledAfterGuard afterGetReferrer=$activityIntentParcelledAfterGetReferrer]")
        for (ep in decisions.keys) append(" $ep=${summary(ep)}")
    }
}

internal object ProbeLog {
    val records = LinkedBlockingQueue<ProbeRecord>()

    fun await(timeoutMs: Long = 20_000): ProbeRecord? = records.poll(timeoutMs, TimeUnit.MILLISECONDS)
}

/** Standard launch mode. Records the launch, returns RESULT_OK (for a for-result caller) and finishes. */
class ProbeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Probe.record(this, intent, Delivery.LAUNCH)
        setResult(RESULT_OK)
        finish()
    }
}

/** `singleTop` (N12): records the launch, stays, records the next `onNewIntent`, then finishes. */
class ProbeSingleTopActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Probe.record(this, intent, Delivery.LAUNCH)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        Probe.record(this, intent, Delivery.NEW_INTENT)
        setResult(RESULT_OK)
        finish()
    }
}

/** Started for result by another app; starts the component in "forward_to" with FLAG_ACTIVITY_FORWARD_RESULT. */
class ForwarderActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val to = intent.getStringExtra("forward_to")?.let(ComponentName::unflattenFromString)
        if (to != null) startActivity(Intent().setComponent(to).addFlags(Intent.FLAG_ACTIVITY_FORWARD_RESULT))
        finish()
    }
}

/** Started by the test; starts [ProbeSingleTopActivity] for result, so its launch has a reliable identity (this app). */
class RequesterActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        startActivityForResult(Intent(this, ProbeSingleTopActivity::class.java), 1)
    }

    @Deprecated("Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        finish()
    }
}

/** A plain Activity of this app. */
class HostActivity : Activity()

/** Declares the App Links filters (manifest); does nothing. */
class LinkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
    }
}
