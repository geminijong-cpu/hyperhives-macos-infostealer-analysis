# Contributing

Contributions that improve defensive value, fix inaccuracies, or extend detection coverage are welcome.

## Accepted contributions

| Category | Examples |
|----------|----------|
| **Detection rules** | New or improved YARA / Sigma rules, Snort/Suricata signatures |
| **IOC updates** | New domains, hashes, IPs, or infrastructure tied to this campaign |
| **Analysis corrections** | Fixing technical errors in the README or output artifacts |
| **Tooling / CI** | Improving `scripts/validate_repo.py`, adding linters, automating exports |
| **Documentation** | Clarifications, typo fixes, translation |
| **STIX / MISP exports** | Improving or extending machine-readable threat-intel bundles |

## Not accepted

- Live malware samples or exploit code
- Persistence mechanisms, weaponized scripts, or offensive tooling
- Unsubstantiated attribution claims (all claims must cite evidence from repository artifacts or public reporting)
- Bulk-generated or AI-generated content without human review

## Before opening a pull request

1. **Validate locally.** Run `python3 scripts/validate_repo.py` to confirm YARA compiles, Sigma YAML parses, and required files exist. The CI workflow runs the same check.
2. **Keep changes small and reviewable.** One logical change per PR.
3. **No binaries.** The `.gitignore` is configured to block samples; do not circumvent it.
4. **Follow existing conventions.**
   - YARA rules: include complete `meta` block (`description`, `author`, `severity`, `date`, `reference`).
   - Sigma rules: include `id`, `status`, `description`, `author`, `date`, `references`, `falsepositives`, `level`, `tags`.
   - IOCs: use the `type:value` format from `iocs.txt`.
5. **Evidence-based.** Cite the artifact, offset, or public report that supports the change.

## Detection rule guidance

- Prefer high-signal strings and conditions that minimise false positives.
- Label heuristic rules clearly in the `meta` block (`severity: medium` or `low`).
- Sigma rules should be backend-neutral where possible and include realistic `falsepositives` notes.
- Test YARA rules against the known sample hash where feasible; test Sigma rules against representative log samples.

## Issue templates

Use the provided [issue templates](.github/ISSUE_TEMPLATE/) for:

- **IOC updates** — new indicators with context and sourcing
- **Detection rule improvements** — rule content, rationale, and testing
- **General issues** — bugs, questions, or suggestions

## Code of conduct

Be constructive, evidence-based, and respectful. This repository deals with active threats; responsible disclosure and operational security matter.

## Safety

All analysis assumes an isolated environment. Read [`SECURITY.md`](SECURITY.md) before reproducing any workflow.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
