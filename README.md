# Android GUI for [WireGuard](https://www.wireguard.com/)

**[Download from the Play Store](https://play.google.com/store/apps/details?id=com.wireguard.android)**

This is an Android GUI for [WireGuard](https://www.wireguard.com/). It [opportunistically uses the kernel implementation](https://git.zx2c4.com/android_kernel_wireguard/about/), and falls back to using the non-root [userspace implementation](https://git.zx2c4.com/wireguard-go/about/).

## Requirements

- **Java 17+**
- **Android SDK** — AGP 9.1.0 编译需要
- **NDK** (侧载版本 28.x) — 用于编译原生 C/Go 库
- **Go ≥ 1.23** — 用于编译 `libwg-go.so`（仅 Linux/macOS 需要；Windows 使用预编译库或系统 Go）
- **Gradle 9.6+** — 项目使用 Gradle Wrapper，自动下载对应版本

## Building

```
$ git clone --recurse-submodules https://git.zx2c4.com/wireguard-android
$ cd wireguard-android
$ ./gradlew assembleRelease
```

或 **Windows cmd/PowerShell**：
```
gradlew.bat assembleDebug
```

### Windows 注意事项

- 原生库 `libwg-go.so` 在 MINGW 环境下使用系统 Go 编译，请确保 Go 已安装
- 如无法从 `services.gradle.org` 下载 Gradle 发行版，可配置代理或手动下载到 `%GRADLE_USER_HOME%/wrapper/dists/`
- macOS 用户可能需要 [flock(1)](https://github.com/discoteq/flock)

### 构建选项

| 命令 | 说明 |
|------|------|
| `assembleDebug` | Debug 版 APK，可直接安装测试 |
| `assembleRelease` | Release 版 APK，需要签名配置 |

## Embedding

The tunnel library is [on Maven Central](https://search.maven.org/artifact/com.wireguard.android/tunnel), alongside [extensive class library documentation](https://javadoc.io/doc/com.wireguard.android/tunnel).

```
implementation 'com.wireguard.android:tunnel:$wireguardTunnelVersion'
```

The library makes use of Java 17 features, so be sure to support those in your gradle configuration with [desugaring](https://developer.android.com/studio/write/java8-support#library-desugaring):

```
compileOptions {
    sourceCompatibility JavaVersion.VERSION_17
    targetCompatibility JavaVersion.VERSION_17
    coreLibraryDesugaringEnabled = true
}
dependencies {
    coreLibraryDesugaring "com.android.tools:desugar_jdk_libs:2.1.5"
}
```

## Translating

Please help us translate the app into several languages on [our translation platform](https://crowdin.com/project/WireGuard).
