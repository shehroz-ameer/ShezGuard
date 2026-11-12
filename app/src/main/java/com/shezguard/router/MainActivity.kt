package com.shezguard.router

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/** Launcher. Takes no input from the intent; it only lists the demo entry points. */
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val version = packageManager.getPackageInfo(packageName, 0).versionName
        setContentView(TextView(this).apply {
            setPadding(48, 48, 48, 48)
            text = """
                ShezGuard VULNERABLE DEMO ($version)
                Emulator only. Never publish. See app/README.md.

                Entry points (threat numbers: docs/SPEC.md section 2):
                1  ForwardActivity        nested intent forwarded
                2  SearchActivity         SQL built from a deep link parameter
                2  PreviewActivity        parameter loaded into a WebView
                2  FileViewerActivity     path built from a parameter
                2  NoteActivity           unbounded extras
                3  RedirectActivity       open redirect via "next"
                4  LinkActivity           hijackable deep links
                5  ProfileActivity        Serializable extra deserialised
                6  ManualCheckActivity    naive hand-written denylist
            """.trimIndent()
        })
    }
}
