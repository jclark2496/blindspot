#!/usr/bin/env python3
"""Build a byte-reproducible Chrome extension ZIP from an explicit allowlist."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
EXTENSION_DIR = ROOT / "extension"
RUNTIME_FILES = (
    "content.js",
    "icons/icon16.png",
    "icons/icon48.png",
    "icons/icon128.png",
    "manifest.json",
    "popup.html",
    "popup.js",
    "rules.js",
)
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def default_output() -> Path:
    version = json.loads((EXTENSION_DIR / "manifest.json").read_text(encoding="utf-8"))["version"]
    return ROOT / "dist" / f"blindspot-extension-{version}.zip"


def build(output: Path) -> Path:
    missing = [name for name in RUNTIME_FILES if not (EXTENSION_DIR / name).is_file()]
    if missing:
        raise SystemExit(f"missing extension runtime file(s): {', '.join(missing)}")

    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_STORED) as archive:
        for name in sorted(RUNTIME_FILES):
            info = ZipInfo(name, date_time=FIXED_TIMESTAMP)
            info.compress_type = ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (EXTENSION_DIR / name).read_bytes())
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="ZIP output path")
    args = parser.parse_args()
    output = build((args.output or default_output()).resolve())
    print(output)


if __name__ == "__main__":
    main()
