package com.shezguard.router

import android.app.Application
import com.shezguard.router.demo.FakeData
import com.shezguard.router.demo.LegacyProfile

/** Creates the fake data on every start (idempotent). Nothing real is stored anywhere. */
class DemoApp : Application() {
    override fun onCreate() {
        super.onCreate()
        FakeData.seed(this)
        // Step 12 (author decision 2): set here, not in ProfileActivity.handle. In the protected flavor
        // ShezGuard deserialises the "profile" extra before handle runs; if this were still set in handle,
        // readObject would return early and the 5b canary would never appear (a false NOT_EXPLOITED).
        LegacyProfile.appFilesDir = filesDir
    }
}
