# Capture and translation workflow

## 1. Produce the inputs

```bash
dpairip -i app.apks -o work
```

This writes `work/app_merged.apk` (the clean, anti-split APK),
`work/app_patched.apk` (logging build), and `work/junk_classes.txt` (the
PairIP junk-class descriptors). The dictionary must come from a running app —
PairIP populates those fields at runtime, so they cannot be derived statically.

## 2a. On-device capture (Termux, no root, no adb)

This is the default logging build. It:

- makes `<application>` debuggable,
- declares `WRITE_EXTERNAL_STORAGE` / `READ_EXTERNAL_STORAGE` for legacy devices,
- writes the JSON to shared storage through `MediaStore` at
  `/sdcard/Download/pairip.json`, plus private and app-specific copies.

Steps: sign `app_patched.apk` with your own key, uninstall the Play build,
install the signed copy, launch it and wait for the main screen, then:

```bash
cp /sdcard/Download/pairip.json work/pairip.json
```

Termux may need `termux-setup-storage` once. On Android 10+ the MediaStore
write needs no permission at all.

Use `--root-flow` to suppress the manifest additions and the shared-storage
write (reference behaviour: private `/data/data/<pkg>/dictionary/pairip.json`
only).

**Caveat:** PairIP's Java signature check is removed, but its native library may
perform additional certificate or environment checks. If the patched build
fails to start, use the stock-app capture below.

## 2b. Stock-app capture with Frida (root required)

Leave the Play-signed app installed, launch it, then:

```bash
pip install 'dpairip[capture]'   # frida 16.x; 17.x removed the Java bridge
dpairip --capture com.example.app -j work/junk_classes.txt -o work/pairip.json
```

Requires `frida-server` 16.x running as root on the device. This path never
runs a modified APK, so native anti-tamper sees the original app.

## 2c. GitHub-hosted emulator (experimental)

`.github/workflows/capture.yml` runs the original signed splits on a rooted
x86_64 emulator (Google Play image, which ships ARM translation), starts
frida-server, and uploads `pairip.json` as an artifact. Dispatch it with the
XAPK URL and package name. GitHub's aarch64 runners cannot install the Android
emulator at all, hence x86_64. This remains experimental: ARM translation may
not support the protected app's native library, and PairIP may refuse to start
inside an emulator.

## 3. Translate

```bash
dpairip -i work/app_merged.apk -t work/pairip.json -o work
```

The dictionary is a JSON object keyed by dotted class name:

```json
{
  "com.example.Foo": {
    "type": "java.lang.String",
    "fields": { "a": "decoded value" }
  },
  "com.example.Bar": {
    "type": "java.lang.reflect.Method",
    "fields": { "b": "public static void com.example.Baz.run()" }
  }
}
```

`dpairip` emits `const-string` + `sput-object` writes for every field, resolves
`Method` values through reflection using `toGenericString()`, and runs the
restore once from the real application's `<clinit>` before app code executes.

## 4. Install

The output is unsigned. Align and sign it yourself, for example:

```bash
zipalign -p 4 app_translated.apk app_aligned.apk
apksigner sign --ks key.jks --out app-signed.apk app_aligned.apk
```
