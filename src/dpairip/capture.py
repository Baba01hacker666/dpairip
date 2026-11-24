"""Optional Frida capture path (``pip install dpairip[capture]``).

When the Play-signed application is still installed, the junk fields can be read
directly from its process.  This avoids installing a rebuilt APK and the
CorePatch/base.apk swap dance entirely.
"""

from __future__ import annotations

import json
import time
from typing import Dict, List

from .errors import ToolError
from .gen.runtime import descriptor_to_class

_SCRIPT = r"""
var names = __JUNK__;
Java.perform(function () {
    var Modifier = Java.use('java.lang.reflect.Modifier');
    var result = {};
    names.forEach(function ( descriptor ) {
        try {
            var clazz = Java.use(descriptor);
            var fields = clazz.class.getDeclaredFields();
            var entry = {type: '', fields: {}};
            for (var i = 0; i < fields.length; i++) {
                try {
                    var field = fields[i];
                    if (!Modifier.isStatic(field.getModifiers())) continue;
                    field.setAccessible(true);
                    if (!entry.type) entry.type = field.getType().getName();
                    var value = field.get(null);
                    entry.fields[field.getName()] = value === null ? null : value.toString();
                } catch (e) {}
            }
            result[descriptor] = entry;
        } catch (e) {}
    });
    send({type: 'done', payload: result});
});
"""


def capture(package: str, junk_file: str, output: str, *, timeout: float = 45.0) -> Dict:
    """Attach to ``package`` and write its populated dictionaries to ``output``."""

    try:
        import frida  # type: ignore
    except ImportError as exc:
        raise ToolError("Frida is not installed; run: pip install 'dpairip[capture]'") from exc

    with open(junk_file, "r", encoding="utf-8") as handle:
        names = [line.strip() for line in handle if line.strip()]
    names = [descriptor_to_class(name) if name.startswith("L") else name for name in names]
    if not names:
        raise ToolError(f"no junk classes in {junk_file}")

    source = _SCRIPT.replace("__JUNK__", json.dumps(names))
    device = frida.get_usb_device(timeout=10)
    session = device.attach(package)
    script = session.create_script(source)
    captured: Dict = {}
    finished = {"value": False}

    def on_message(message, _data) -> None:
        payload = message.get("payload") if message.get("type") == "send" else None
        if isinstance(payload, dict) and payload.get("type") == "done":
            captured.update(payload.get("payload", {}))
            finished["value"] = True

    script.on("message", on_message)
    script.load()
    deadline = time.monotonic() + timeout
    while not finished["value"] and time.monotonic() < deadline:
        time.sleep(0.1)
    script.unload()
    session.detach()

    if not finished["value"]:
        raise ToolError("timed out waiting for the Frida capture")
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(captured, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return captured
