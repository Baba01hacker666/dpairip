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

## 2c. Embedded Frida Gadget (no root, no adb)

This route runs Frida **inside the app process** and hides it behind a renamed
native library. Download the matching Gadget from Frida releases
(`frida-gadget-16.7.19-android-arm64.so.xz`), then:

```bash
dpairip -i app.apks --embed-gadget /path/to/frida-gadget-android-arm64.so -o work
```

dpairip installs it as `lib/arm64-v8a/libdpairip.so` with two siblings:

- `libdpairip.config.so` — Gadget **script mode**, pointing at the bundled script
- `libdpairip.script.so` — the JavaScript, with the junk-class list and output
  path baked in

No TCP port is opened and no Frida client or root is needed. The generated
Application loads the renamed Gadget from `<clinit>`, before PairIP's native
library initialises, so the script's hooks are installed first. The script:

- masks marker strings in `strcmp`/`strncmp`/`strcasecmp`,
- spoofs `ro.debuggable`/`ro.secure` through `__system_property_get`,
- waits until the junk fields are populated, then reflects over them and writes
  the dictionary to `/data/data/<package>/files/pairip.json`.

The Java dumper in the same build also writes the public copy to
`/sdcard/Download/pairip.json`, which is the one you can read from Termux:

```bash
# sign + install work/app_patched.apk, launch it, wait for the main screen
cp /sdcard/Download/pairip.json work/pairip.json
dpairip -i work/app_merged.apk -t work/pairip.json
```

This is a starting point for anti-detection, not a guarantee: PairIP builds
check strings on the stack and use `dl_iterate_phdr`/`readdir`, so some builds
may need additional hooks in the bundled script. The library rename defeats
simple "loaded library contains frida" checks.

`--gadget-connect HOST:PORT` remains available if you prefer a listen-mode
gadget with a live client, but script mode is the default and needs no port.

## 2d. Why no GitHub-hosted emulator

All runner architectures were tested against a real ARM-only PairIP target;
none can run the protected native library:

- **Linux aarch64 runner**: Google does not publish an `emulator` SDK package
  for aarch64 Linux — `sdkmanager --install emulator` fails with
  `Failed to find package 'emulator'`.
- **Linux x86_64 + KVM**: the emulator boots and the app installs, but the
  ARM64 `libpairipcore.so` crashes under ARM translation:
  `Unexpected CPU variant for X86 using defaults: x86_64` followed by
  `Fatal signal 11 (SIGSEGV), code 128 (SI_KERNEL), fault addr 0x0`.
- **macOS arm64 runner**: Hypervisor.framework is unavailable inside the
  GitHub VM (`HVF error: HV_UNSUPPORTED`, `failed to initialize HVF`).
  `-accel off` plus `ANDROID_I_WANT_MY_TCG=yes` still makes QEMU exit
  immediately with `QEMU main loop exits abnormally with code 1`, so the
  TCG fallback cannot boot the ARM64 guest either.

A physical ARM device is therefore required: rooted with frida-server for the
stock-app flow, or unmodified root for the default patched build. No emulator
workflow is shipped.

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
