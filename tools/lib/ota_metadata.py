"""
OTA metadata extractor.

Reads the META-INF/com/android/metadata file from an OTA zip and
parses the key=value pairs into a structured dict.
"""

import zipfile
from typing import Optional


# Fields we always want to capture if present
IMPORTANT_FIELDS = [
    "ota-id",
    "ota_version",
    "version_name",
    "version_name_show",
    "android_version",
    "display_os_version",
    "os_version",
    "post-build",
    "post-build-incremental",
    "post-sdk-level",
    "post-security-patch-level",
    "post-timestamp",
    "pre-device",
    "product_name",
    "security_patch",
    "security_patch_vendor",
    "google_patch",
    "ota-type",
    "patch_type",
    "wipe",
    "build_type",
]


def extract_ota_metadata(zip_path: str) -> Optional[dict]:
    """Extract metadata from an OTA zip file.

    Reads META-INF/com/android/metadata and returns a dict of all
    key=value pairs found.  Returns None if the metadata file is
    not found.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            try:
                raw = zf.read("META-INF/com/android/metadata")
            except KeyError:
                return None
    except (zipfile.BadZipFile, Exception):
        return None

    text = raw.decode("utf-8", errors="replace").strip()
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line:
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()

    return result


def extract_payload_list(zip_path: str) -> list[str]:
    """List partitions available in the OTA payload.

    This uses payload_dumper --list, but as a fallback just returns
    an empty list.
    """
    import subprocess
    import shutil

    dumper = shutil.which("payload_dumper")
    if dumper is None:
        # Try our local copy
        import os
        local = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "..", "tools", "payload_dumper", "payload_dumper"
        )
        if os.path.isfile(local):
            dumper = local
        else:
            return []

    try:
        result = subprocess.run(
            [dumper, zip_path, "--list"],
            capture_output=True, text=True, timeout=60
        )
        lines = result.stdout.strip().splitlines()
        partitions = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("Partition"):
                continue
            name = line.split()[0]
            if name:
                partitions.append(name)
        return partitions
    except Exception:
        return []
