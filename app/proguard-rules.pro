# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile
# Step 12: the demo's LegacyProfile is a Serializable kept for "backward compatibility" (threat 5b); the app
# itself never constructs one, only deserialisation does. The usual Serializable rules
# (-keepnames + -keepclassmembers { serialVersionUID; readObject; ... }) are NOT enough for such a class:
# R8 sees no instantiation, makes the class abstract and removes readObject and the instance fields
# anyway (observed in step 12, docs/ATTACK_MATRIX.md, R8 section). Deserialising an instance of the
# abstract class then crashed ART natively (SIGSEGV) inside ShezGuard's extras inspection, and made the
# vulnerable flavor's own toString print raw memory. Keep the whole class, constructor included, so it
# stays concrete and keeps its name, fields and readObject, as in the debug build.
-keep class com.shezguard.router.demo.LegacyProfile { *; }
