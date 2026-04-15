package com.duckduckgo.android_crashkit

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

@RunWith(RobolectricTestRunner::class)
class CrashpadTest {

    private lateinit var context: Application
    private lateinit var markerFile: File

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        markerFile = File(context.filesDir, "crashpad/crash_marker")
        markerFile.parentFile?.mkdirs()
        markerFile.delete()

        // Simulate library loaded; bypass the JNI guard
        Crashpad.libraryLoaded = true
        Crashpad.inited = false
    }

    @After
    fun tearDown() {
        Crashpad.inited = false
        Crashpad.libraryLoaded = false
        markerFile.delete()
    }

    @Test
    fun `onCrash called when marker file exists`() {
        markerFile.createNewFile()
        var called = false

        Crashpad.init(context, platform = "test", version = "0", osVersion = "0", config = CrashpadConfig(onCrash = { called = true }))

        assertTrue(called)
    }

    @Test
    fun `onCrash not called when marker file absent`() {
        var called = false

        Crashpad.init(context, platform = "test", version = "0", osVersion = "0", config = CrashpadConfig(onCrash = { called = true }))

        assertFalse(called)
    }

    @Test
    fun `marker file deleted after onCrash is invoked`() {
        markerFile.createNewFile()

        Crashpad.init(context, platform = "test", version = "0", osVersion = "0", config = CrashpadConfig(onCrash = {}))

        assertFalse(markerFile.exists())
    }

    @Test
    fun `marker file left intact when onCrash is null`() {
        markerFile.createNewFile()

        Crashpad.init(context, platform = "test", version = "0", osVersion = "0", config = CrashpadConfig(onCrash = null))

        assertTrue(markerFile.exists())
    }

    @Test
    fun `onCrash not called when marker file absent and onCrash is null`() {
        // No exception or side effects expected
        Crashpad.init(context, platform = "test", version = "0", osVersion = "0", config = CrashpadConfig(onCrash = null))
    }

    @Test
    fun `init returns false when library not loaded`() {
        Crashpad.libraryLoaded = false

        val result = Crashpad.init(context, platform = "test", version = "0", osVersion = "0")

        assertFalse(result)
    }

    @Test
    fun `crash returns false when library not loaded`() {
        Crashpad.libraryLoaded = false

        assertFalse(Crashpad.crash())
    }

    @Test
    fun `dumpWithoutCrash returns false when library not loaded`() {
        Crashpad.libraryLoaded = false

        assertFalse(Crashpad.dumpWithoutCrash())
    }

    @Test
    fun `onCrash invoked before native init so callback always fires even if native fails`() {
        markerFile.createNewFile()
        var called = false

        // initializeCrashpad will fail (no native lib), but onCrash must still be called
        Crashpad.init(context, platform = "test", version = "0", osVersion = "0", config = CrashpadConfig(onCrash = { called = true }))

        assertTrue(called)
    }

    @Test
    fun `init is idempotent — second call returns true without re-running`() {
        Crashpad.inited = true
        var called = false
        markerFile.createNewFile()

        val result = Crashpad.init(context, platform = "test", version = "0", osVersion = "0", config = CrashpadConfig(onCrash = { called = true }))

        assertTrue(result)
        assertFalse("onCrash must not fire on second init", called)
        assertTrue("marker must not be deleted on second init", markerFile.exists())
    }
}
