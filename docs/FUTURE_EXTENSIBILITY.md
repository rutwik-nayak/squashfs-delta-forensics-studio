# Future Extensibility Plan

## 1) Extractor Expansion

- Add unsquashfs export parser as a dedicated extractor
- Add custom extractor adapters for in-house metadata
- Add extractor auto-detection from header signatures
- Add support for LZ4/LZO/XZ compressed SquashFS metadata blocks
- Add support for reading SquashFS directory tables to resolve inode paths

## 2) Analysis Upgrades

- Multi-build timeline mode (N-way comparison)
- Directory-level churn attribution
- More accurate compressed block correlation
- ML-assisted reuse-loss root-cause ranking
- Enable blast radius analytics when SquashFS image extraction provides
  authoritative file->fragment membership

## 3) Visualization Upgrades

- Delta playback across build history
- Fragment topology map with zoom clustering
- Exportable evidence bundles (PNG/PDF snapshots)

## 4) Reliability and Validation

- JSON schema validation in analyzer pipeline
- Golden sample test suite
- Cross-check mode against independent extractor outputs
- Unit tests for SquashFS superblock/inode/fragment-table parsing

## 5) Integrations

- CLI packaging for CI artifact generation
- Optional static site bundling for publishable forensic reports
- Canonical model export/import for offline analysis
