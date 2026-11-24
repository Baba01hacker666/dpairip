"""Bundle a renamed Frida Gadget into the logging build.

The gadget is loaded from the generated Application's ``<clinit>`` before the
protector's native library runs. It is renamed to an innocuous library name and
configured through the sibling ``.config.so`` file that Frida looks for on
Android. Connect with ``dpairip --gadget-connect HOST:PORT`` from the device.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from ..apks import Module


def embed_gadget(
    module: Module,
    gadget_path: str,
    *,
    abi: str = "arm64-v8a",
    libname: str = "dpairip",
    port: int = 27042,
    on_load: str = "wait",
) -> Dict[str, str]:
    """Add the gadget binary and its config to the APK native library folders."""

    payload = Path(gadget_path).read_bytes()
    if len(payload) < 1024:
        raise ValueError("gadget binary looks too small")

    config = {
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": port,
            "on_load": on_load,
        },
        "code_signing": "optional",
        "teardown": -1,
    }
    library = f"lib/{abi}/lib{libname}.so"
    config_file = f"lib/{abi}/lib{libname}.config.so"
    module.apk.put(library, payload, compress=False)
    module.apk.put(config_file, json.dumps(config).encode("utf-8"), compress=False)
    return {"library": library, "config": config_file, "port": str(port), "abi": abi}
