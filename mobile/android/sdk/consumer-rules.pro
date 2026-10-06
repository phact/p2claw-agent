# ProGuard / R8 rules the SDK ships to consumer apps. Keeps UniFFI's
# generated runtime classes intact across consumer-side minification —
# JNA reflects on them by name and a renaming pass would silently break
# the FFI.

-keep class uniffi.p2claw_mobile.** { *; }
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.* { *; }
