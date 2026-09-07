from __future__ import annotations

import json
import shutil
from pathlib import Path


def copy_report_to_web_data(report_path: Path, web_data_dir: Path) -> Path:
    web_data_dir.mkdir(parents=True, exist_ok=True)
    target = web_data_dir / "report.json"
    shutil.copyfile(report_path, target)
    return target


def write_inline_report_js(report_path: Path, web_data_dir: Path) -> Path:
    web_data_dir.mkdir(parents=True, exist_ok=True)
    target = web_data_dir / "report.inline.js"
    with report_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)

    payload = json.dumps(report, separators=(",", ":"))
    with target.open("w", encoding="utf-8") as handle:
        handle.write("window.__FORENSICS_REPORT__ = ")
        handle.write(payload)
        handle.write(";\n")
    return target


def create_web_bundle(web_root: Path, bundle_output: Path) -> Path:
    """Create a portable zip bundle of the complete web folder."""
    web_root = web_root.resolve()
    bundle_output = bundle_output.resolve()
    bundle_output.parent.mkdir(parents=True, exist_ok=True)

    base_name = bundle_output.with_suffix("")
    archive_path = Path(shutil.make_archive(str(base_name), "zip", root_dir=str(web_root.parent), base_dir=web_root.name))

    # Ensure exact caller-provided output name when suffixes differ.
    if archive_path != bundle_output:
        shutil.move(str(archive_path), str(bundle_output))
        return bundle_output
    return archive_path
