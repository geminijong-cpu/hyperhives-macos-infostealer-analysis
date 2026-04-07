# Changelog

All notable changes to this repository are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2026-04-07

### Summary

Initial public release of the HyperHives macOS infostealer analysis with full threat-intelligence exports.

### Included

- **Full technical report** (`README.md`) — binary analysis, decrypted C2 infrastructure, social-engineering kill chain (Wellfound fake job pipeline), MITRE ATT&CK mapping (18 techniques), 276 targeted Chrome extension IDs, and attribution assessment.
- **Decryption pipeline** (`scripts/decrypt_all.py`) — Unicorn CPU emulation of 570 unique x86_64 helpers, recovering all 571 encrypted configuration values.
- **Machine-readable outputs** (`output/`) — `full_decrypted_config.json`, `iocs.json`, C2 protocol documentation, Cargo dependency list, reconstructed source map.
- **Detection rules** — `yara_rules.yar` (4 rules: hash match + heuristic), `sigma_rules.yml` (6 rules: proxy, DNS, process creation).
- **STIX 2.1 bundle** (`stix/bundle.json`) — malware, infrastructure, indicators, ATT&CK patterns, and relationships.
- **ATT&CK Navigator layer** (`attack-navigator-layer.json`) — 18 observed techniques for visual import.
- **Flat IOC list** (`iocs.txt`) — hashes, domains, URLs, IPs, email, Sentry IDs, social-engineering context.
- **Isolated analysis environment** — `Dockerfile`, `docker-compose.yml` (air-gapped, read-only, capabilities dropped), `lab.sh` helper.
- **Repository infrastructure** — CI validation workflow, issue templates, PR template, `SECURITY.md`, `CONTRIBUTING.md`, MIT license.
