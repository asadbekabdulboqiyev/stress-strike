# White-labeling Guide

## Branding
- Rename binary: `go build -o yourname ./cmd/stress-strike`
- Update README/docs references as needed
- Configurable report headers via scenario/config if desired

## Artifacts
- Reports generated in `reports/` with scenario name
- Audit/log paths configurable via env/flags

## Minimal steps
1. Build with desired name
2. Update metadata in packaging (Chart.yaml, goreleaser if used)
3. Generate white-label PDF using `scripts/gen-white-label-pdf.sh`

See `scripts/gen-white-label-pdf.sh` for details.
