from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forensics_studio.parsers.base import BaseFragmentMetadataParser


class FragmentJsonParser(BaseFragmentMetadataParser):
    """Read optional fragment metadata dump as JSON.

    Expected shape:
    {
      "fragments": {
        "100": {
          "compressed_size": 1234,
          "files": ["/a", "/b"]
        }
      }
    }

    Also accepts a top-level object keyed by fragment IDs directly.
    """

    def parse(self, input_path: Path) -> dict[str, dict[str, Any]]:
        with input_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if isinstance(payload, dict) and "fragments" in payload and isinstance(payload["fragments"], dict):
            data = payload["fragments"]
        elif isinstance(payload, dict):
            data = payload
        else:
            raise ValueError(f"Unsupported fragment metadata format in {input_path}")

        normalized: dict[str, dict[str, Any]] = {}
        for fragment_id, meta in data.items():
            fragment_key = str(fragment_id)
            if not isinstance(meta, dict):
                continue
            normalized[fragment_key] = {
                "compressed_size": meta.get("compressed_size"),
                "files": list(meta.get("files", [])),
            }

        return normalized
