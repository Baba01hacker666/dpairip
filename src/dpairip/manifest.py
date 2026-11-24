"""AndroidManifest patching for repacked applications."""

from __future__ import annotations

from typing import List, Optional

from . import axml

# attributes that only make sense for a split APK bundle
_SPLIT_RESOURCE_IDS = (
    axml.RES_REQUIRED_SPLIT_TYPES,
    axml.RES_SPLIT_TYPES,
    axml.RES_IS_SPLIT_REQUIRED,
    axml.RES_IS_FEATURE_SPLIT,
)
_SPLIT_ATTRIBUTE_NAMES = (
    "requiredSplitTypes",
    "splitTypes",
    "isSplitRequired",
    "isFeatureSplit",
    "split",
)

# bundle bookkeeping that the package manager would otherwise trust
_STAMP_META_DATA = (
    "com.android.stamp.source",
    "com.android.stamp.type",
    "com.android.vending.splits",
    "com.android.vending.derived.apk.id",
    "com.android.dynamic.apk.fused.modules",
    "com.android.vending.splits.required",
)

_PAIRIP_COMPONENTS = (
    ("activity", "com.pairip.licensecheck.LicenseActivity"),
    ("provider", "com.pairip.licensecheck.LicenseContentProvider"),
    ("service", "com.pairip.licensecheck.LicenseService"),
)

_PAIRIP_PERMISSIONS = ("com.android.vending.CHECK_LICENSE",)


def patch(document: axml.Document, application_class: Optional[str] = None) -> dict:
    """Normalise a manifest so the merged/repacked APK installs standalone."""
    pool = document.pool
    root = document.root
    if root is None:
        return {}

    stats = {"attributes": 0, "components": 0, "meta_data": 0, "permissions": 0}

    stats["attributes"] += axml.remove_attributes(
        root, pool, names=_SPLIT_ATTRIBUTE_NAMES, resource_ids=_SPLIT_RESOURCE_IDS
    )

    application = document.element("manifest/application")
    if application is not None:
        for attribute in list(application.attributes):
            if pool.get(attribute.name) in _SPLIT_ATTRIBUTE_NAMES:
                application.attributes.remove(attribute)
                stats["attributes"] += 1
        native_libs = application.attribute(
            pool, resource_id=axml.RES_EXTRACT_NATIVE_LIBS
        )
        if native_libs is None or axml.bool_value(pool, native_libs) is False:
            axml.set_attribute_bool(
                application,
                pool,
                "extractNativeLibs",
                True,
                resource_id=axml.RES_EXTRACT_NATIVE_LIBS,
            )

    if application_class:
        target = application
        if target is None:
            target = document.element("manifest")
        if target is not None:
            axml.set_attribute_string(target, pool, "name", application_class)

    for tag, class_name in _PAIRIP_COMPONENTS:
        for element in list(_all_with_tag(root, tag, pool)):
            if _android_name(document, element) == class_name:
                element.remove()
                stats["components"] += 1

    for element in list(_all_with_tag(root, "meta-data", pool)):
        if _android_name(document, element) in _STAMP_META_DATA:
            element.remove()
            stats["meta_data"] += 1

    for element in list(_all_with_tag(root, "uses-permission", pool)):
        if _android_name(document, element) in _PAIRIP_PERMISSIONS:
            element.remove()
            stats["permissions"] += 1

    return stats


def _all_with_tag(element: Optional[axml.Element], tag: str, pool: axml.StringPool):
    if element is None:
        return
    for child in list(element.children):
        if pool.get(child.name) == tag:
            yield child
        yield from _all_with_tag(child, tag, pool)


def _android_name(document: axml.Document, element: axml.Element) -> str:
    attribute = element.attribute(
        document.pool, resource_id=axml.RES_NAME
    ) or element.attribute(document.pool, name="name")
    if attribute is None:
        return ""
    return document.pool.get(attribute.data) if attribute.data_type == axml.TYPE_STRING else ""


def application_class(document: axml.Document) -> str:
    application = document.element("manifest/application")
    if application is None:
        return ""
    return _android_name(document, application)


def split_name(document: axml.Document) -> str:
    root = document.root
    if root is None:
        return ""
    attribute = root.attribute(document.pool, name="split")
    if attribute is None:
        return ""
    return document.pool.get(attribute.data) if attribute.data_type == axml.TYPE_STRING else ""


def add_permission(document: axml.Document, permission: str) -> bool:
    """Declare a permission if the manifest does not already have it."""

    pool = document.pool
    root = document.root
    if root is None or permission in permissions(document):
        return False

    existing = next(iter(_all_with_tag(root, "uses-permission", pool)), None)
    if existing is not None and existing.attributes:
        namespace = existing.attributes[0].ns
    elif root.namespace_start is not None:
        namespace = root.namespace_start.uri
    else:
        namespace = pool.index_of("http://schemas.android.com/apk/res/android")

    value = pool.index_of(permission)
    element = axml.Element(
        axml.CHUNK_START_ELEMENT, name=pool.index_of("uses-permission"), ns=axml.NO_ENTRY
    )
    element.attributes.append(
        axml.Attribute(namespace, pool.index_of("name"), value,
                       axml.TYPE_STRING, value)
    )
    root.children.insert(0, element)
    element.parent = root
    return True


def permissions(document: axml.Document) -> List[str]:
    root = document.root
    return [
        _android_name(document, element)
        for element in _all_with_tag(root, "uses-permission", document.pool)
    ]
