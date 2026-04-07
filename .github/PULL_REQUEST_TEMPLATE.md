## Summary

<!-- One-paragraph description of the change. -->

## Type of change

- [ ] IOC update (new indicators)
- [ ] Detection rule (YARA / Sigma)
- [ ] Documentation / analysis correction
- [ ] Tooling / CI improvement
- [ ] Other

## Checklist

- [ ] YARA rules compile without errors (`yara -C yara_rules.yar`)
- [ ] Sigma YAML is valid (`python -c "import yaml; list(yaml.safe_load_all(open('sigma_rules.yml')))"`)
- [ ] No live malware, exploit code, or PII included
- [ ] Changes are evidence-based and referenced
- [ ] `scripts/validate_repo.py` passes locally
