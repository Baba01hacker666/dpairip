# Architecture

## Modules

| Module | Purpose |
|---|---|
| `dpairip.dex.reader` / `writer` | Complete DEX parse and rebuild (pools, class data, code, annotations, encoded values, method handles, call sites) |
| `dpairip.dex.insns` | Opcode table, instruction sizing, branch/payload fix-ups, symbolic encoder |
| `dpairip.dex.model` | Name-based IR — descriptors instead of pool indices |
| `dpairip.axml` | Binary AndroidManifest reader/writer and attribute helpers |
| `dpairip.apk` | ZIP reader/writer with alignment and CRC-field patching |
| `dpairip.apks` | Bundle merging, lazy dex IR, raw in-place dex patching |
| `dpairip.gen` | Symbolic assembler plus generated runtime classes |
| `dpairip.patches` | Logging and translation transforms |
| `dpairip.manifest` | Manifest rule set (split attributes, components, permissions) |
| `dpairip.capture` | Frida capture client (optional `capture` extra) |

## DEX strategy

The IR uses descriptor strings instead of numeric indices. Every transform is
`parse → mutate → write`, with identifier pools re-sorted and checksums
recomputed. This avoids index-insertion problems and lets classes be added or
removed freely. Debug information is intentionally dropped when a dex is
rebuilt.

## Logging mode

- Junk classes are detected structurally: no methods, static `String` /
  `Method` fields with no initial values, `public class` extending `Object`.
- The void `SignatureCheck.verifyIntegrity(Context)` call is replaced with
  equally sized `nop`s in the raw dex bytes; code offsets do not move and the
  dex header signature/checksum are repaired.
- A new dex is appended containing `Ldpairip/runtime/Dumper;` and
  `Ldpairip/runtime/Application;`. The latter extends the original manifest
  application class, so the protector's startup sequence still runs via
  `super`; the dump runs after `attachBaseContext` and `onCreate` have returned.
- The dumper reflects over the junk fields, builds the dictionary JSON and
  writes it to shared and private storage. All I/O is wrapped in catch-all
  handlers so a storage failure cannot crash the app.

## Translation mode

- The real application class is derived from the superclass of
  `com.pairip.application.Application`; the manifest is repointed at it.
- PairIP classes are replaced by inert stubs under their original names, so
  existing references keep resolving without rewriting every dex.
- `Bridge.launch()` is injected at the start of the real application's
  `<clinit>`; it runs a guarded one-shot `restore()` that writes the captured
  field values. Restore code is chunked to keep method sizes bounded.
- Embedded dex images are recovered from asset blobs (`00 49 41 50 02` header
  and zip containers) and added as new dexes; duplicate types are resolved in
  favour of the recovered classes.
- `libpairipcore.so` entries are removed and the manifest is normalised.

## Runtime namespace

All generated classes live under `Ldpairip/runtime/` (`Dumper`, `Bridge`,
`MethodLookup`, `Application`) so they cannot collide with application classes.
