package com.shezguard.core.device.probe

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue

/**
 * Shell commands from the instrumented test (uid 2000 via `UiAutomation`), emulator only.
 * `scripts/device/run_shared_tests.sh` pushes the `:attacker` APK to [ATTACKER_APK] and refuses to
 * run on a physical device; without the APK the caller tests are skipped, not passed.
 */
internal object DeviceShell {
    const val ATTACKER_APK = "/data/local/tmp/shezguard-attacker.apk"

    fun run(cmd: String): String {
        val pfd = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(cmd)
        return ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().use { it.readText() }
    }

    /**
     * Uninstalls and reinstalls `:attacker`, so no implicit visibility grant from an earlier test
     * remains (on API 30+ the grants are dropped with the package).
     */
    fun freshAttacker() {
        assumeTrue(
            "attacker APK not pushed to $ATTACKER_APK (run scripts/device/run_shared_tests.sh)",
            run("ls $ATTACKER_APK").trim() == ATTACKER_APK,
        )
        run("pm uninstall ${Probe.ATTACKER}")
        val out = run("pm install -t $ATTACKER_APK")
        assertTrue("pm install: $out", out.contains("Success"))
    }

    /** Starts `:attacker`'s IdentityActivity from the shell, so the test APK never resolves the attacker itself. */
    fun attacker(mode: String, target: Class<*>, vararg extras: Pair<String, String>) {
        val args = StringBuilder("am start -n ${Probe.ATTACKER}/.IdentityActivity --es mode $mode --es target ${Probe.SELF}/${target.name}")
        for ((k, v) in extras) args.append(" --es $k $v")
        run(args.toString())
    }
}
