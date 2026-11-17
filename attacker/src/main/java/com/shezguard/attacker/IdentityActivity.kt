package com.shezguard.attacker

import android.app.Activity
import android.app.ActivityOptions
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Parcel
import android.util.Log

/**
 * Step 14 phase 2 (emulator only): launches a component of ShezGuard's instrumented test APK
 * (`com.shezguard.core.test`) in a chosen way, so the test can see what the target's platform APIs
 * and ShezGuard report about the caller. Started from the shell by the test:
 * `am start -n com.shezguard.attacker/.IdentityActivity --es mode <mode> --es target <component>`.
 *
 * Modes:
 * - `plain`: `startActivity`, no extras.
 * - `for_result`: `startActivityForResult`; waits for the result, then finishes.
 * - `share_identity`: `startActivity` with `ActivityOptions.setShareIdentityEnabled(true)` (API 34+).
 * - `forward_result`: `startActivityForResult` on the test's ForwarderActivity, which forwards the
 *   result slot to `target` (`FLAG_ACTIVITY_FORWARD_RESULT`).
 * - `referrer_extra` / `referrer_name`: spoofed `EXTRA_REFERRER` / `EXTRA_REFERRER_NAME` naming the demo
 *   app, plus one ordinary extra.
 * - `extras_only`: one ordinary extra and no referrer.
 * - `new_intent`: `FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_SINGLE_TOP` (delivers to `onNewIntent` of a
 *   `singleTop` target on top of its task).
 * - `uri_mismatch`: `ACTION_VIEW` whose data is a `Uri` built from a hand-written parcel with
 *   representation `BOTH` and disagreeing encoded and decoded paths (N4). If this platform's
 *   `Uri.CREATOR` rejects the bytes, nothing is sent and the failure is logged with the `nonce` extra.
 */
class IdentityActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val mode = intent.getStringExtra("mode")
        val target = intent.getStringExtra("target")?.let(ComponentName::unflattenFromString)
        if (target == null) {
            Log.e(TAG, "missing target"); finish(); return
        }
        val base = Intent().setComponent(target)
        Log.i(TAG, "identity mode=$mode target=${target.flattenToShortString()}")
        @Suppress("DEPRECATION")
        when (mode) {
            "plain" -> startActivity(base)
            "for_result" -> { startActivityForResult(base, 1); return }
            "share_identity" -> if (Build.VERSION.SDK_INT >= 34) {
                startActivity(base, ActivityOptions.makeBasic().setShareIdentityEnabled(true).toBundle())
            } else {
                Log.e(TAG, "share_identity needs API 34")
            }
            "forward_result" -> {
                val forwarder = Intent().setComponent(ComponentName(target.packageName, FORWARDER))
                    .putExtra("forward_to", target.flattenToString())
                startActivityForResult(forwarder, 2)
                return
            }
            "referrer_extra" -> startActivity(
                base.putExtra(Intent.EXTRA_REFERRER, Uri.parse("android-app://$ROUTER")).putExtra("k", "v"),
            )
            "referrer_name" -> startActivity(
                base.putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://$ROUTER").putExtra("k", "v"),
            )
            "extras_only" -> startActivity(base.putExtra("k", "v"))
            "new_intent" -> startActivity(base.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP))
            "uri_mismatch" -> {
                val nonce = intent.getStringExtra("nonce")
                try {
                    val uri = craftedUri(encodedPath = "/product/1", decodedPath = "/admin/../../secret")
                    Log.i(TAG, "uri_mismatch nonce=$nonce crafted toString=<$uri> getPath=<${uri.path}>")
                    startActivity(base.setAction(Intent.ACTION_VIEW).setData(uri))
                } catch (e: RuntimeException) {
                    Log.i(TAG, "uri_mismatch nonce=$nonce craft failed: ${e.javaClass.name}: ${e.message}")
                }
            }
            else -> Log.e(TAG, "unknown identity mode: $mode")
        }
        finish()
    }

    @Deprecated("Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        Log.i(TAG, "identity result request=$requestCode code=$resultCode")
        finish()
    }

    /** The same bytes as ShezGuard's `CraftedUriParcelTest` (API 24-29 `HierarchicalUri` format). */
    private fun craftedUri(encodedPath: String, decodedPath: String): Uri {
        val p = Parcel.obtain()
        try {
            p.writeInt(3) // HierarchicalUri.TYPE_ID
            p.writeString("https")
            p.writeInt(0); p.writeString("example.com"); p.writeString("example.com") // authority, BOTH
            p.writeInt(0); p.writeString(encodedPath); p.writeString(decodedPath)     // path, BOTH
            p.writeInt(0); p.writeString("id=1"); p.writeString("id=1")               // query, BOTH
            p.writeInt(1); p.writeString(null)                                        // fragment: ENCODED, none
            p.setDataPosition(0)
            return Uri.CREATOR.createFromParcel(p)
        } finally {
            p.recycle()
        }
    }

    private companion object {
        const val TAG = AttackActivity.TAG
        const val ROUTER = AttackActivity.VICTIM
        const val FORWARDER = "com.shezguard.core.device.probe.ForwarderActivity"
    }
}
