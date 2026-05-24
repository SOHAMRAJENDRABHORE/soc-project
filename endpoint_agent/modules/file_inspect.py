"""Inspect specific files: hashes, size, mtime."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from shared.logger import get_logger

log = get_logger(__name__)


def _hash_file(path: Path) -> dict:
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                for h in hashes.values():
                    h.update(chunk)
    except Exception as e:
        return {"error": str(e)}
    return {k: h.hexdigest() for k, h in hashes.items()}


def run(params: dict) -> dict:
    """
    params:
      paths: list[str] of files to inspect
    """
    paths = params.get("paths", [])
    if isinstance(paths, str):
        paths = [paths]

    results = []
    for p in paths:
        path = Path(p)
        item: dict = {"path": str(path)}
        if not path.exists():
            item["exists"] = False
            results.append(item)
            continue
        item["exists"] = True
        try:
            stat = path.stat()
            item["size_bytes"] = stat.st_size
            item["mtime"] = stat.st_mtime
            item["mode_octal"] = oct(stat.st_mode)
            if path.is_file() and stat.st_size < 200 * 1024 * 1024:  # cap at 200 MB
                item["hashes"] = _hash_file(path)
            else:
                item["hashes"] = {"skipped": "file too large or not a regular file"}
        except Exception as e:
            item["error"] = str(e)
        results.append(item)
    return {"inspected": results}
