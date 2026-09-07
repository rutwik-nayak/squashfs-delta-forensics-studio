from __future__ import annotations

import argparse
from pathlib import Path

from forensics_studio.analyzer.engine import ForensicsAnalyzer
from forensics_studio.extractors.registry import ExtractorRegistry
from forensics_studio.reporting.generator import write_debug_dataset, write_report
from forensics_studio.utils.io import copy_report_to_web_data, create_web_bundle, write_inline_report_js


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SquashFS Delta Forensics Studio analyzer")
    parser.add_argument("--old-map", type=Path, default=None, help="Path to old unsquashfs map file")
    parser.add_argument("--new-map", type=Path, default=None, help="Path to new unsquashfs map file")
    parser.add_argument("--old-image", type=Path, default=None, help="Path to old SquashFS image (preferred source)")
    parser.add_argument("--new-image", type=Path, default=None, help="Path to new SquashFS image (preferred source)")
    parser.add_argument("--old-fragments", type=Path, default=None)
    parser.add_argument("--new-fragments", type=Path, default=None)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--debug-output", type=Path, default=None, help="Path for debug_dataset.json export")
    parser.add_argument("--copy-to-web", action="store_true", help="Copy output report to web/assets/data/report.json")
    parser.add_argument("--web-data-dir", type=Path, default=Path("web/assets/data"))
    parser.add_argument("--bundle-web", action="store_true", help="Create a portable zip bundle of the full web report UI")
    parser.add_argument("--web-root", type=Path, default=Path("web"), help="Root web folder to bundle")
    parser.add_argument(
        "--bundle-output",
        type=Path,
        default=Path("samples/outputs/squashfs-delta-forensics-web-bundle.zip"),
        help="Output zip path for portable web bundle",
    )
    return parser


def _resolve_source(
    image_path: Path | None,
    map_path: Path | None,
    registry: ExtractorRegistry,
) -> Path:
    """Resolve the source path, preferring the SquashFS image when provided."""
    if image_path is not None:
        return image_path
    if map_path is not None:
        return map_path
    raise ValueError("Either --old-image/--new-image or --old-map/--new-map must be provided")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    registry = ExtractorRegistry()

    old_source = _resolve_source(args.old_image, args.old_map, registry)
    new_source = _resolve_source(args.new_image, args.new_map, registry)

    old_extractor = registry.get_extractor(old_source)
    new_extractor = registry.get_extractor(new_source)

    old_model = old_extractor.extract(old_source)
    new_model = new_extractor.extract(new_source)

    analyzer = ForensicsAnalyzer()
    result = analyzer.analyze(
        old_model=old_model,
        new_model=new_model,
        old_fragment_path=args.old_fragments,
        new_fragment_path=args.new_fragments,
    )

    write_report(result, args.output)
    debug_output = args.debug_output or (args.output.parent / "debug_dataset.json")
    write_debug_dataset(result, debug_output)

    if args.copy_to_web or args.bundle_web:
        copy_report_to_web_data(args.output, args.web_data_dir)
        write_inline_report_js(args.output, args.web_data_dir)

    if args.bundle_web:
        create_web_bundle(args.web_root, args.bundle_output)


if __name__ == "__main__":
    main()
