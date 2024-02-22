plugins {
    id("com.android.application")
}

android {
    namespace = "mfsx.xposed.trustmealready"
    compileSdk = 34

    defaultConfig {
        applicationId = "mfsx.xposed.trustmealready"
        minSdk = 15
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
}