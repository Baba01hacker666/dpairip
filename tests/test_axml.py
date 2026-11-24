from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from dpairip import axml, manifest

SAMPLE = Path("/home/baba01hacker/apks/tracket/tracket.apk")


def _sample_manifest() -> bytes:
    if not SAMPLE.exists():
        pytest.skip("no local sample APK")
    with zipfile.ZipFile(SAMPLE) as archive:
        return archive.read("AndroidManifest.xml")


def test_manifest_round_trip_byte_identical():
    original = _sample_manifest()
    assert axml.parse(original).to_bytes() == original


def test_manifest_helpers():
    document = axml.parse(_sample_manifest())
    assert document.element("manifest") is not None
    assert manifest.application_class(document) == "com.pairip.application.Application"
    assert manifest.permissions(document)

    app = document.element("manifest/application")
    before = manifest.application_class(document)
    axml.set_attribute_string(app, document.pool, "name", "com.example.Real")
    reparsed = axml.parse(document.to_bytes())
    assert manifest.application_class(reparsed) == "com.example.Real"
    assert manifest.application_class(axml.parse(_sample_manifest())) == before
