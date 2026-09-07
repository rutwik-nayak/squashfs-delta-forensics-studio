from __future__ import annotations

from pathlib import Path

from forensics_studio.parsers.base import BaseFragmentMetadataParser, BaseMapParser
from forensics_studio.parsers.fragment_json_parser import FragmentJsonParser
from forensics_studio.parsers.map_parser import GenericMapParser


class ParserRegistry:
    """Resolver for parser implementations by file name/extension."""

    def get_map_parser(self, input_path: Path) -> BaseMapParser:
        _ = input_path
        return GenericMapParser()

    def get_fragment_parser(self, input_path: Path) -> BaseFragmentMetadataParser:
        suffix = input_path.suffix.lower()
        if suffix == ".json":
            return FragmentJsonParser()
        raise ValueError(f"No fragment parser registered for extension: {suffix}")
