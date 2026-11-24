"""Bundle a renamed Frida Gadget and its inbuilt script into the logging build.

Gadget runs in *script* mode: the JavaScript is shipped inside the APK, so no
TCP port is opened and no external Frida client is needed. The script installs
anti-detection hooks before the protector's native library initialises, waits
for the VM to populate the junk fields, then writes ``pairip.json`` itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Sequence

from ..apks import Module
from ..capture import _GADGET_SCRIPT


def embed_gadget(
    module: Module,
    gadget_path: str,
    *,
    abi: str = "arm64-v8a",
    libname: str = "dpairip",
    port: int = 27042,
    junk: Sequence[str] = (),
    output: str = "/data/data/%s/files/pairip.json",
    listen: bool = False,
) -> Dict[str, str]:
    """Add a renamed Gadget, its config and the bundled script to the APK."""

    payload = Path(gadget_path).read_bytes()
    if len(payload) < 1024:
        raise ValueError("gadget binary looks too small")

    script_name = f"lib{libname}.script.so"
    config_name = f"lib{libname}.config.so"
    library = f"lib/{abi}/lib{libname}.so"

    if listen:
        interaction = {
            "type": "listen",
            "address": "127.0.0.1",
            "port": port,
            "on_load": "wait",
        }
    else:
        interaction = {"type": "script", "path": script_name, "on_change": "ignore"}
        source = (_GADGET_SCRIPT
                  .replace("__JUNK__", json.dumps(list(junk)))
                  .replace("__OUTPUT__", json.dumps(output)))
        module.apk.put(f"lib/{abi}/{script_name}", source.encode("utf-8"), compress=False)

    config = {
        "interaction": interaction,
        "code_signing": "optional",
        "teardown": -1,
    }
    module.apk.put(library, payload, compress=False)
    module.apk.put(f"lib/{abi}/{config_name}",
                   json.dumps(config).encode("utf-8"), compress=False)
    return {
        "library": library,
        "config": f"lib/{abi}/{config_name}",
        "script": f"lib/{abi}/{script_name}" if not listen else "",
        "abi": abi,
    }
