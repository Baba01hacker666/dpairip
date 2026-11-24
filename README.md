# dpairip

A pure-Python PairIP / VMRunner unpacker for Android APK, APKS and XAPK files.

dpairip merges split bundles, records the dictionary that PairIP's VM populates
at runtime, and rebuilds a clean, translated APK from that dictionary. No Java,
no bundled dex blobs, no apktool/MT Manager, no external binaries — all dex
classes are generated and assembled by dpairip itself.

**Author: baba01hacker** · MIT licensed.

## Install

```bash
pip install dpairip
# optional: Frida-based dictionary capture (requires frida-server 16.x)
pip install 'dpairip[capture]'
```

Requires Python 3.9+. From a checkout: `pip install -e .`

## Quick start

```bash
# 1. merge splits + add the dictionary logger
dpairip -i app.apks

# 2. obtain pairip.json from the running app (see docs/workflow.md)
#    on-device (Termux): cp /sdcard/Download/pairip.json .
#    via Frida:          dpairip --capture com.example.app -j junk_classes.txt -o pairip.json

# 3. translate the clean merged APK
dpairip -i app_merged.apk -t pairip.json
```

Outputs are written beside the input unless `-o DIR` is given:

| Input | Outputs |
|---|---|
| `app.apks` / `.xapk` | `app_merged.apk`, `app_patched.apk`, `junk_classes.txt` |
| `app.apk` | `app_patched.apk`, `junk_classes.txt` |
| `-t pairip.json` | `app_translated.apk` |

Sign and zipalign translated APKs before installing; dpairip does not sign.

## Options

```
-i, --input APK       input .apk / .apks / .xapk
-o, --output DIR      output directory (default: input directory)
-t, --translate JSON  pairip.json to bake in
-j, --junk FILE       destination for the junk class list
    --capture PKG     capture pairip.json from a running app via Frida
    --non-root        default: shared-storage dump + debuggable manifest
    --root-flow       private dump only, no manifest additions
    --pull-dump PKG   optional: adb pull the dump from a PC workflow
    --no-crc          do not restore original dex CRC fields
    --no-strip-integrity  keep PairIP's integrity call in the logging build
-v, --version         print the version
-h, --help            print help
```

## How it works

- **DEX engine** — full reader/writer for identifier pools, class data, code
  items, try/catch, annotations, encoded values, method handles and call sites.
  Parse → mutate → rebuild with sorted pools and recomputed checksums.
- **Logging mode** — leaves the original dexes byte-identical except for a
  three-unit `nop` over the void integrity call. The dumper and a thin
  `Application` subclass live in an appended dex.
- **Translation mode** — restores the captured values into the junk-class static
  fields, replaces the protector's classes with inert stubs, recovers embedded
  dex images from assets, removes `libpairipcore.so` and repoints the manifest
  at the real application class.
- **Binary XML / ZIP** — in-place AndroidManifest editing and a custom ZIP
  writer with 4 KB alignment for native libraries.

Detailed notes: [`docs/workflow.md`](docs/workflow.md),
[`docs/architecture.md`](docs/architecture.md).

## Limitations

- Split resource tables and `res/` entries are not merged; the base resource
  table stays authoritative.
- Stubbed protector methods return zero/null.
- APKs are unsigned; signing is the user's responsibility.
- The native protector library may implement checks beyond the Java integrity
  call. See [`docs/workflow.md`](docs/workflow.md) for capture options.
- Use only on applications you are authorised to analyse.

## Development

```bash
python -m pytest -q
```

The suite builds a synthetic PairIP-like APK and exercises both patch modes
end to end; no device or third-party binary is required.

## License

MIT — Copyright (c) baba01hacker. See [LICENSE](LICENSE).
