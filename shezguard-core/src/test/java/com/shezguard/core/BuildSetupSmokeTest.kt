package com.shezguard.core

import android.net.Uri
import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Proves the unit-test setup works: JUnit runs, and Robolectric provides real
 * Android framework classes (`android.net.Uri`) at the pinned SDK level.
 * Later Robolectric tests (evaluator, differential URI parsing) rely on this.
 */
@RunWith(RobolectricTestRunner::class)
class BuildSetupSmokeTest {

    @Test
    fun robolectricProvidesRealAndroidUri() {
        val uri = Uri.parse("https://example.com/product/42?id=42")

        assertEquals("https", uri.scheme)
        assertEquals("example.com", uri.host)
        assertEquals("42", uri.getQueryParameter("id"))
    }

    @Test
    fun robolectricRunsAtPinnedSdk() {
        assertEquals(34, Build.VERSION.SDK_INT)
    }
}
