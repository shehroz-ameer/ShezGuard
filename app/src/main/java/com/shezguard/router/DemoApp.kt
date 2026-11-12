package com.shezguard.router

import android.app.Application
import com.shezguard.router.demo.FakeData

/** Creates the fake data on every start (idempotent). Nothing real is stored anywhere. */
class DemoApp : Application() {
    override fun onCreate() {
        super.onCreate()
        FakeData.seed(this)
    }
}
