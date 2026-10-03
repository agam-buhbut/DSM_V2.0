# UniFFI generated bindings use JNA, which relies on reflection over the
# native-mapped interfaces. Keep the JNA runtime and the generated bindings.
-keep class com.sun.jna.** { *; }
-keep interface com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keep class uniffi.tuncore.** { *; }
