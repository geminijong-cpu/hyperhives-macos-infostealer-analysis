# Security Policy

## Purpose

This repository contains **threat-intelligence artifacts derived from malware analysis**. It does **not** distribute live malware samples, exploit code, or weaponized tooling.

## Safe handling guidelines

| Rule | Detail |
|------|--------|
| **Never execute** the sample on a production or personal host | Use the provided Docker environment (`network_mode: none`, `read_only: true`, all capabilities dropped) |
| **Never commit** live binaries to Git | The `.gitignore` blocks known sample filenames; `sample/README.md` describes how to place the sample locally |
| **Treat IOCs as defensive data** | Hashes, URLs, and extension IDs are for blocking, hunting, and attribution — not offensive use |
| **Validate detection rules** before production deployment | YARA and Sigma rules should be tuned and tested in your own environment |

## Reproducing the analysis

```bash
# Build the air-gapped container
docker compose build

# Run the decryptor (no network, read-only root, capabilities dropped)
docker compose run --rm lab python3 /lab/scripts/decrypt_all.py
```

Full environment details are in `Dockerfile`, `docker-compose.yml`, and `lab.sh`.

## Supported versions

This repository tracks a single malware campaign and is versioned in [`CHANGELOG.md`](CHANGELOG.md). There is no "supported version" in the traditional software sense — all releases contain the latest IOCs and detection rules.

## Reporting a vulnerability

If you discover that this repository inadvertently exposes sensitive data, contains a live sample, or has a CI/CD security issue:

1. **Do not** open a public issue.
2. Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository.
3. Expect an initial response within 72 hours.

## Reporting campaign abuse

For criminal activity related to the HyperHives / `cloudproxy.link` campaign documented here:

- Contact your national CERT or equivalent (e.g., US-CERT, NCSC, JPCERT)
- File a report with law enforcement (e.g., IC3, Action Fraud)
- Report the domains/IPs to the hosting providers and registrars identified in the README
- Report the Sentry account to Sentry's abuse team

## Disclaimer

IOCs and detection rules are provided **as-is** for defensive purposes. The authors make no warranty regarding accuracy, completeness, or fitness for any particular use. Blocking shared-hosting IPs or benign APIs (e.g., `freeipapi.com`) may cause collateral impact — verify before deploying.
