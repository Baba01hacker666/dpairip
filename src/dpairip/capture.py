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


_EVASION_SCRIPT = r"""
// Installed before the gadget releases the app (on_load = wait).
var MARKERS = ['frida', 'gadget', 'xposed', 'substrate', 'cydia', 'magisk'];

function matches(text) {
    if (!text) return false;
    var lower = text.toLowerCase();
    for (var i = 0; i < MARKERS.length; i++) {
        if (lower.indexOf(MARKERS[i]) !== -1) return true;
    }
    return false;
}

function maskComparisons() {
    ['strcmp', 'strncmp', 'strcasecmp'].forEach(function (name) {
        var address = Module.findExportByName(null, name);
        if (!address) return;
        Interceptor.attach(address, {
            onEnter: function (args) {
                var a = null, b = null;
                try { a = args[0].readUtf8String(); } catch (e) {}
                try { b = args[1].readUtf8String(); } catch (e) {}
                if (matches(a) || matches(b)) this.skip = true;
            },
            onLeave: function (retval) {
                if (this.skip) retval.replace(1);
            }
        });
    });
}

function maskProperties() {
    var address = Module.findExportByName(null, '__system_property_get');
    if (!address) return;
    Interceptor.attach(address, {
        onEnter: function (args) {
            try {
                var name = args[0].readUtf8String();
                if (name === 'ro.debuggable' || name === 'ro.secure') {
                    this.fix = args[2];
                }
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (this.fix && retval.toInt32() > 0) {
                this.fix.writeUtf8String('0');
                retval.replace(1);
            }
        }
    });
}

function watchLoads() {
    ['dlopen', 'android_dlopen_ext'].forEach(function (name) {
        var address = Module.findExportByName(null, name);
        if (!address) return;
        Interceptor.attach(address, {
            onEnter: function (args) {
                var path = null;
                try { path = args[0].readUtf8String(); } catch (e) {}
                if (path) console.log('[dpairip] dlopen: ' + path);
            }
        });
    });
}

maskComparisons();
maskProperties();
watchLoads();

var junk = [];
rpc.exports = {
    setJunk: function (names) { junk = names; },
    dump: function () {
        var result = {};
        Java.perform(function () {
            var Modifier = Java.use('java.lang.reflect.Modifier');
            junk.forEach(function (name) {
                try {
                    var clazz = Java.use(name);
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
                    result[name] = entry;
                } catch (e) {}
            });
        });
        return JSON.stringify(result);
    }
};
console.log('[dpairip] gadget hooks installed');
"""


def connect_gadget(
    address: str, junk_file: str, output: str, *, timeout: float = 60.0
) -> Dict:
    """Connect to an embedded Gadget listening on ``address`` and dump fields."""

    try:
        import frida  # type: ignore
    except ImportError as exc:
        raise ToolError("Frida is not installed; run: pip install 'dpairip[capture]'") from exc

    with open(junk_file, "r", encoding="utf-8") as handle:
        names = [line.strip() for line in handle if line.strip()]
    names = [descriptor_to_class(name) if name.startswith("L") else name for name in names]
    if not names:
        raise ToolError(f"no junk classes in {junk_file}")

    manager = frida.get_device_manager()
    device = manager.add_remote_device(address)
    try:
        session = device.attach("Gadget")
    except Exception as exc:
        raise ToolError(f"could not attach to Gadget at {address}: {exc}") from exc

    messages: List[str] = []
    script = session.create_script(_EVASION_SCRIPT)
    script.on("message", lambda message, _data: messages.append(str(message)))
    script.load()
    try:
        device.resume("Gadget")
    except Exception:
        pass  # on_load = resume

    time.sleep(15)  # let the protector populate the junk fields
    exports = script.exports_sync
    exports.set_junk(names)
    payload = exports.dump()
    result = json.loads(payload)
    script.unload()
    session.detach()

    with open(output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return {"dictionary": result, "messages": messages}


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
