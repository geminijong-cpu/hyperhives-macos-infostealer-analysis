#!/usr/bin/env python3
"""
Repository validation for public release.

Checks:
  - Required top-level files exist
  - YARA rules compile (requires yara-python)
  - Sigma YAML parses as multiple documents (requires pyyaml)
  - STIX bundle is valid JSON with required top-level keys
  - ATT&CK Navigator layer is valid JSON with required keys
  - Decrypted config JSON loads successfully
"""

from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parent.parent


def validate_required_files() -> None:
    required = [
        ROOT / "README.md",
        ROOT / "LICENSE",
        ROOT / "SECURITY.md",
        ROOT / "CHANGELOG.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "iocs.txt",
        ROOT / "yara_rules.yar",
        ROOT / "sigma_rules.yml",
        ROOT / "stix" / "bundle.json",
        ROOT / "attack-navigator-layer.json",
        ROOT / "output" / "full_decrypted_config.json",
        ROOT / ".github" / "workflows" / "validate.yml",
        ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md",
    ]
    missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
    if missing:
        raise SystemExit(f"missing required files: {', '.join(missing)}")
    print(f"  [OK] {len(required)} required files present")


def validate_yara() -> None:
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise SystemExit(f"unable to import yara module: {exc}")
    try:
        rules = yara.compile(filepath=str(ROOT / "yara_rules.yar"))
    except Exception as exc:
        raise SystemExit(f"yara validation failed: {exc}")
    print("  [OK] YARA rules compile")


def validate_sigma_yaml() -> None:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise SystemExit(f"unable to import yaml module: {exc}")
    docs = list(yaml.safe_load_all((ROOT / "sigma_rules.yml").read_text()))
    docs = [d for d in docs if d is not None]
    if not docs:
        raise SystemExit("sigma_rules.yml contains no YAML documents")
    if not all(isinstance(d, dict) for d in docs):
        raise SystemExit("sigma_rules.yml contains non-mapping YAML documents")
    for i, doc in enumerate(docs):
        for key in ("title", "id", "status", "detection"):
            if key not in doc:
                raise SystemExit(f"sigma rule {i} missing required key '{key}'")
    print(f"  [OK] {len(docs)} Sigma rules parse with required keys")


def validate_stix_bundle() -> None:
    path = ROOT / "stix" / "bundle.json"
    try:
        bundle = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"stix/bundle.json is not valid JSON: {exc}")
    if bundle.get("type") != "bundle":
        raise SystemExit("stix/bundle.json: top-level 'type' must be 'bundle'")
    if "objects" not in bundle:
        raise SystemExit("stix/bundle.json: missing 'objects' array")
    obj_types = {o.get("type") for o in bundle["objects"]}
    for required_type in ("malware", "indicator", "relationship", "report"):
        if required_type not in obj_types:
            raise SystemExit(f"stix/bundle.json: missing object type '{required_type}'")
    print(f"  [OK] STIX bundle: {len(bundle['objects'])} objects, types: {sorted(obj_types)}")


def validate_attack_navigator() -> None:
    path = ROOT / "attack-navigator-layer.json"
    try:
        layer = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"attack-navigator-layer.json is not valid JSON: {exc}")
    for key in ("name", "domain", "techniques", "versions"):
        if key not in layer:
            raise SystemExit(f"attack-navigator-layer.json: missing key '{key}'")
    techniques = layer["techniques"]
    if not techniques:
        raise SystemExit("attack-navigator-layer.json: 'techniques' array is empty")
    ids = {t.get("techniqueID") for t in techniques}
    print(f"  [OK] ATT&CK Navigator layer: {len(ids)} techniques")


def validate_decrypted_config() -> None:
    path = ROOT / "output" / "full_decrypted_config.json"
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"output/full_decrypted_config.json is not valid JSON: {exc}")
    if "total_decrypted" not in data:
        raise SystemExit("output/full_decrypted_config.json: missing 'total_decrypted'")
    print(f"  [OK] Decrypted config: {data['total_decrypted']} entries")


def main() -> int:
    print("Validating repository artifacts...")
    validate_required_files()
    validate_yara()
    validate_sigma_yaml()
    validate_stix_bundle()
    validate_attack_navigator()
    validate_decrypted_config()
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
