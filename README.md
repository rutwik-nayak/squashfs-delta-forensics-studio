# SquashFS Delta Forensics Studio

SquashFS Delta Forensics Studio is a local, static forensic workbench for analyzing SquashFS filesystem changes, reuse behavior, storage layout churn, and structural movement between image revisions.

The project helps engineers understand *why* filesystem layouts change and where reuse opportunities may be lost, using direct metadata extraction and explainable root-cause analysis.

It focuses on:

- SquashFS structure analysis
- Fragment layout and churn
- File layout and block-chain churn
- Storage movement across revisions
- Reuse opportunity identification
- Explainable root-cause reporting

It does **not** depend on OTA payload parsing and does not require `payload.bin`.

---

## Project Status

The project is under active development.

Current focus areas include:

- Direct SquashFS metadata extraction
- Reuse opportunity analysis
- Layout churn detection
- Fragment movement analysis
- Offset cascade investigation
- Explainable forensic reporting

The architecture is designed to support additional metadata sources and analysis modules in future releases.

---

## Why This Exists

Traditional filesystem comparison tools can identify what changed, but often provide limited visibility into why structural changes occurred or how those changes affect reuse opportunities.

SquashFS Delta Forensics Studio focuses on explainable forensic analysis, helping engineers understand:

- What changed?
- What moved?
- Where was reuse lost?
- What structures contributed most to churn?
- What changes had the largest downstream impact?

---

## Features

### Metadata Extraction

- Direct SquashFS image extraction
- Unsquashfs map ingestion
- Extensible extraction framework
- Canonical intermediate representation

### Filesystem Analysis

- Fragment layout analysis
- Offset movement detection
- Block-chain churn analysis
- File movement tracking
- Storage layout comparison
- Reuse opportunity ranking

### Root Cause Investigation

- Root cause classification
- Confidence scoring
- Blast radius analysis
- Parser traceability
- Movement cascade detection

### Reporting

- JSON report generation
- Debug dataset export
- Static visualization dashboard
- Portable web bundle generation

### Safety and Validation

- Data confidence model (HIGH, MEDIUM, LOW)
- Parser validation workflow
- Source traceability
- Synthetic-data detection and warnings

---

## Design Goals

- Local-first workflow
- No backend server
- No database dependency
- Explainable analysis results
- Extensible architecture
- Reproducible reporting

---

## Architecture Overview

```text
Input Sources
    ↓
Metadata Extraction Layer
    ↓
CanonicalImageModel
    ↓
ForensicsAnalyzer
    ↓
report.json
    ↓
Visualization Studio
```

---

## Project Structure

### Core Analysis Package

`forensics_studio/`

- `extractors/`
  - Metadata extraction layer
  - SquashFS image extraction
  - Map-based extraction

- `models/`
  - Canonical data model
  - Typed analysis records

- `analyzer/`
  - Core analysis engine

- `parsers/`
  - Legacy and compatibility parsers

- `reporting/`
  - Report generation

- `utils/`
  - Shared helpers and utilities

### Supporting Components

- `schema/`
  - JSON report schema

- `web/`
  - Static forensic visualization studio

- `docs/`
  - Architecture and design documentation

- `samples/`
  - Synthetic demonstration datasets

---

## Documentation

- `docs/ARCHITECTURE.md` — System architecture and design principles
- `docs/ROADMAP.md` — Planned improvements and future work
- `docs/JSON_MODEL.md` — Canonical model and report contracts
- `docs/WIREFRAMES.md` — Visualization studio wireframes
- `docs/FUTURE_ENHANCEMENTS.md` — Long-term vision and capabilities

---

## Quick Start

### Analyze SquashFS Images

```bash
PYTHONPATH=. python3 scripts/run_analysis.py \
  --old-image squashfs_images/rootfs_a.img \
  --new-image squashfs_images/rootfs_b.img \
  --output samples/outputs/report.json
```

### Analyze Map Files

```bash
PYTHONPATH=. python3 scripts/run_analysis.py \
  --old-map samples/inputs/old.map \
  --new-map samples/inputs/new.map \
  --old-fragments samples/inputs/old_fragment_dump.json \
  --new-fragments samples/inputs/new_fragment_dump.json \
  --output samples/outputs/report.json
```

### Generate Portable Web Bundle

```bash
PYTHONPATH=. python3 scripts/run_analysis.py \
  --old-image squashfs_images/rootfs_a.img \
  --new-image squashfs_images/rootfs_b.img \
  --output samples/outputs/report_rootfs_a_b.json \
  --bundle-web \
  --bundle-output samples/outputs/squashfs-delta-forensics-web-bundle.zip
```

---

## Visualization Studio

Open:

```text
web/report.html
```

directly in a web browser.

If local file restrictions prevent data loading via `fetch`, use the built-in report loader to import a generated report manually.

When executed with `--copy-to-web`, the analyzer also generates:

```text
web/assets/data/report.inline.js
```

allowing portable offline report bundles.

---

## Metadata Extraction Layer

The extraction layer converts source data into a canonical representation.

Analysis components consume only the canonical model, ensuring separation between:

- Source formats
- Parsing logic
- Analysis logic
- Reporting logic

### Supported Sources

- SquashFS images
- Unsquashfs map files

### Source Preference

When available, direct SquashFS extraction is preferred because it provides the richest available source of filesystem metadata and may expose relationships that map-based formats do not contain.

### Extending the System

Additional source types can be added by implementing a new extractor and registering it through:

```text
forensics_studio/extractors/registry.py
```

---

## Confidence Model

### HIGH

Direct metadata obtained from SquashFS extraction.

### MEDIUM

Multiple independent metadata sources are available.

### LOW

Partial metadata availability or limited parser confidence.

When required relationships are unavailable, dependent analyses are disabled and clearly reported as:

```text
Unavailable: not present in source
```

---

## Independent Dataset Mode

Hybrid maps containing both fragment entries and file entries are supported.

The analyzer treats these sections as independent datasets and avoids inferring relationships that are not explicitly present in the source metadata.

Available analysis includes:

- File offset comparison
- File layout churn
- Block-chain comparison
- Offset cascade detection
- Fragment movement analysis
- Fragment size evolution

---

## Debug Export

Each run can generate a debug dataset that includes:

- Files
- Fragments
- Blocks
- Extents
- Relationships
- Source records
- Parser assumptions

This dataset is intended for troubleshooting and validation workflows.

---

## Input Compatibility

Required:

- `--old-image` and `--new-image`

or

- `--old-map` and `--new-map`

Optional:

- `--old-fragments`
- `--new-fragments`

Hybrid map layouts containing fragment-table and file-layout sections are supported.

---

## Disclaimer

This project is an independent engineering tool designed for filesystem analysis and experimentation.

All datasets included in this repository are synthetic and provided exclusively for demonstration, testing, and validation purposes.

No proprietary firmware images, OTA payloads, customer data, confidential datasets, vendor-specific filesystem metadata, or restricted materials are included in this repository.

---

## Contributing

Contributions are welcome.

Please see `CONTRIBUTING.md` for contribution guidelines and development principles.

Only synthetic datasets should be committed to the repository. Do not contribute proprietary firmware images, confidential metadata, or customer data.