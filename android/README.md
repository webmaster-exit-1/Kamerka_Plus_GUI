# Kamerka Plus Android

This directory contains a standalone Android Studio project for a native **Kamerka Plus** app scaffold. It is isolated from the Python/Django codebase in the repository root, so you can work on the Android client without changing the existing web application setup.

## Requirements

- Android Studio Ladybug or newer
- JDK 17 (bundled with recent Android Studio releases)
- Android SDK Platform 35
- Android SDK Build-Tools installed by Android Studio during sync

## Open the project

1. Clone the repository normally.
2. In Android Studio, choose **Open**.
3. Select the `/android` directory in this repository.
4. Let Android Studio sync the Gradle files and install any missing SDK components.

## Build a debug APK

### From Android Studio

- Use **Build > Build Bundle(s) / APK(s) > Build APK(s)**.

### From the command line

From the repository root:

```bash
cd android
./gradlew assembleDebug
```

The debug APK will be generated at:

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

## Project layout

- `settings.gradle.kts` / `build.gradle.kts` / `gradle.properties` — Android Gradle project configuration
- `app/` — Kotlin + Jetpack Compose application module
- `.gitignore` — Android-only ignore rules for Gradle and local SDK files

