"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from typing import List, Optional, Sequence

from . import log
from .apks import Module
from .apk import patch_dex_crc
from .errors import DpairipError
from .patches import patch_logging, patch_translation

VERSION = "1.0.0"

_BANNER = """\
dpairip {version} - pure Python PairIP/VMRunner unpacker
author: baba01hacker
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dpairip",
        description=("Merge an APK bundle, add a dictionary logger or translate a "
                     "PairIP-protected application using a captured pairip.json."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  dpairip -i app.apks                       merge + add logging runtime\n"
            "  dpairip -i app.apks -t pairip.json         translate with captured dictionary\n"
            "  dpairip -i app.apks --capture com.example   capture with Frida instead\n"
        ),
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="store_true", help="show this help")
    parser.add_argument("-v", "--version", action="store_true", help="show the version")
    parser.add_argument("-i", "--input", metavar="APK", help="input .apk/.apks/.xapk")
    parser.add_argument("-o", "--output", metavar="DIR", help="output directory")
    parser.add_argument("-t", "--translate", metavar="JSON", help="pairip.json to bake in")
    parser.add_argument("-j", "--junk", metavar="FILE", help="junk class list destination")
    parser.add_argument("--capture", metavar="PACKAGE",
                        help="capture pairip.json from a running app using Frida")
    parser.add_argument("--pull-dump", metavar="PACKAGE",
                        help="adb pull pairip.json written by a non-root logging build")
    parser.add_argument("--non-root", action="store_true",
                        help="(default) shared-storage dump + debuggable manifest")
    parser.add_argument("--root-flow", action="store_true",
                        help="reference flow only: private dump, no manifest extras")
    parser.add_argument("--no-crc", action="store_true",
                        help="do not copy original dex CRC values into the patched APK")
    parser.add_argument("--no-strip-integrity", action="store_true",
                        help="keep PairIP's integrity call in the logging build")
    parser.add_argument("--verbose", action="store_true", help="extra diagnostics")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    return parser


def _stem(path: str) -> str:
    name = os.path.basename(path)
    stem = os.path.splitext(name)[0]
    for suffix in ("_merged", "_patched", "_translated"):
        if stem.endswith(suffix):
            stem = stem[:-len(suffix)]
    return stem


def _source_crcs(path: str) -> dict:
    crcs = {}
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.filename.startswith("classes") and info.filename.endswith(".dex"):
                    crcs[info.filename] = info.CRC
    except (OSError, zipfile.BadZipFile):
        pass
    return crcs


def _run_capture(args: argparse.Namespace) -> int:
    from .capture import capture

    junk = args.junk or os.path.join(os.getcwd(), "junk_classes.txt")
    output = args.output or os.path.join(os.getcwd(), "pairip.json")
    if not os.path.isfile(junk):
        log.error(f"junk class list not found: {junk}")
        return 2
    capture(args.capture, junk, output)
    log.build(f"dictionary written to {output}")
    return 0


def _adb() -> str:
    found = shutil.which("adb")
    if found:
        return found
    fallback = os.path.expanduser("~/android-sdk/platform-tools/adb")
    if os.path.isfile(fallback):
        return fallback
    raise DpairipError("adb was not found on PATH")


def _run_pull(args: argparse.Namespace) -> int:
    package = args.pull_dump
    destination = args.output or os.path.join(os.getcwd(), "pairip.json")
    try:
        adb = _adb()
        remote = f"/sdcard/Android/data/{package}/files/pairip.json"
        result = subprocess.run([adb, "pull", remote, destination],
                                capture_output=True, text=True)
        if result.returncode != 0:
            # debuggable builds can also be read from the private directory
            result = subprocess.run(
                [adb, "exec-out", "run-as", package, "cat",
                 f"/data/data/{package}/dictionary/pairip.json"],
                capture_output=True,
            )
            if result.returncode != 0 or not result.stdout.strip():
                log.error("dump not found; is the patched app installed and launched?")
                log.error(result.stderr.decode("utf-8", "replace").strip())
                return 1
            with open(destination, "wb") as handle:
                handle.write(result.stdout)
        with open(destination, "rb") as handle:
            if not handle.read(2):
                raise DpairipError("dump file is empty")
        log.build(f"dictionary pulled to {destination}")
        return 0
    except DpairipError as exc:
        log.error(str(exc))
        return 1
    except OSError as exc:
        log.error(f"adb failed: {exc}")
        return 1


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    log.configure(verbose=args.verbose, colour=False if args.no_color else None)

    if args.help:
        print(_parser().format_help())
        return 0
    if args.version:
        print(f"dpairip {VERSION}")
        return 0
    if args.capture:
        return _run_capture(args)
    if args.pull_dump:
        return _run_pull(args)
    if not args.input:
        log.error("missing option --input")
        return 2
    if not os.path.isfile(args.input):
        log.error(f"input file not found: {args.input}")
        return 2
    if args.translate and not os.path.isfile(args.translate):
        log.error(f"translation file not found: {args.translate}")
        return 2

    print(_BANNER.format(version=VERSION), file=sys.stderr)
    output_dir = args.output or os.path.dirname(os.path.abspath(args.input))
    os.makedirs(output_dir, exist_ok=True)
    stem = _stem(args.input)
    is_bundle = not args.input.lower().endswith(".apk")

    try:
        merged_path: Optional[str] = None
        if is_bundle:
            module = Module.from_bundle(args.input)
            merged_path = os.path.join(output_dir, stem + "_merged.apk")
            module.save(merged_path)
            log.build(f"merged APK written to {merged_path}")
        else:
            module = Module.load(args.input)
            log.info(f"loaded {args.input}")

        if args.translate:
            result = patch_translation(module, args.translate)
            output = os.path.join(output_dir, stem + "_translated.apk")
        else:
            result = patch_logging(module,
                                   strip_integrity=not args.no_strip_integrity,
                                   non_root=not args.root_flow)
            output = os.path.join(output_dir, stem + "_patched.apk")

        module.save(output)
        log.build(f"output written to {output}")

        if not args.translate:
            junk_path = args.junk or os.path.join(output_dir, "junk_classes.txt")
            with open(junk_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(result["junk"]))
                if result["junk"]:
                    handle.write("\n")
            log.build(f"junk class list written to {junk_path}")
            if not args.root_flow:
                log.info("on-device flow: sign/install the patched APK, launch it once, "
                         "then: cp /sdcard/Download/pairip.json .   (no root, no adb)")

            if merged_path and not args.no_crc:
                crcs = _source_crcs(merged_path)
                patched = patch_dex_crc(output, crcs)
                if patched:
                    log.build(f"restored {len(patched)} original dex CRC value(s)")
        return 0
    except DpairipError as exc:
        log.error(str(exc))
        return 1
    except Exception as exc:  # pragma: no cover - last resort for malformed inputs
        log.error(f"{type(exc).__name__}: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main(argv: Optional[Sequence[str]] = None) -> None:
    raise SystemExit(run(argv))


if __name__ == "__main__":  # pragma: no cover
    main()
