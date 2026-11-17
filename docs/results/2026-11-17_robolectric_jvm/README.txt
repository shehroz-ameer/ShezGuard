Robolectric (JVM) reference for the step 14 device comparison: JUnit XML of the six src/sharedTest classes from
./gradlew :shezguard-core:test (testDebugUnitTest), run 2026-11-17 after the move to src/sharedTest.
The full JVM test-name lists (896 per variant) are jvm_test*UnitTest_names.txt; identical to the lists before the move.
Robolectric is not a device: it runs AOSP Java code on the JVM with an emulated native Parcel.
