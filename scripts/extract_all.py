#!/usr/bin/env python3
"""
Extract everything useful from the binary into organized files.
Creates a complete analysis package in /lab/output/ that you can
browse in your IDE.

Usage (inside container):
    python3 /lab/scripts/extract_all.py
"""

import re
import json
import struct
import subprocess
from pathlib import Path

SAMPLE = Path("/lab/sample/installer_binary")
OUTPUT = Path("/lab/output")

def main():
    data = SAMPLE.read_bytes()

    print("Extracting all analysis artifacts...\n")

    # 1. Source map
    src_map = extract_source_map(data)
    save("source_map.txt", src_map)

    # 2. All strings categorized
    strings_report = extract_strings(data)
    save("strings_report.txt", strings_report)

    # 3. Cargo dependencies (from registry paths)
    deps = extract_dependencies(data)
    save("cargo_dependencies.txt", deps)

    # 4. C2 protocol spec
    c2_spec = extract_c2_protocol(data)
    save("c2_protocol.txt", c2_spec)

    # 5. Targeted apps and data
    targets = extract_targets(data)
    save("targets.txt", targets)

    # 6. Encrypted config hex dump
    config_dump = extract_encrypted_config(data)
    save("encrypted_config.hex", config_dump)

    # 7. IOC summary
    iocs = generate_iocs(data)
    save("iocs.json", json.dumps(iocs, indent=2))

    # 8. Mach-O sections hex dump
    dump_sections(data)

    print(f"\nAll artifacts saved to {OUTPUT}/")
    print("Open ~/malware-lab/output/ in your IDE to review.")

def extract_source_map(data):
    """Map the malware's source code structure."""
    lines = ["MALWARE SOURCE CODE STRUCTURE", "=" * 50, ""]
    lines.append("Compiled by: /Users/rootr/ (macOS)")
    lines.append("Toolchain:   rustc 1.87.0 stable")
    lines.append("Sentry SDK:  0.36.0")
    lines.append("")

    # Get malware's own source files (not library code)
    own_files = set()
    lib_files = set()
    paths = re.findall(rb'(src/[a-zA-Z0-9_/]+\.rs)', data)
    for p in sorted(set(p.decode() for p in paths)):
        # Heuristic: malware's own code vs library code
        if any(k in p for k in ['pussy', 'browser', 'consts', 'main.rs', 'utils.rs']):
            own_files.add(p)
        elif p.startswith('src/') and '/' not in p[4:]:
            own_files.add(p)

    lines.append("MALWARE OWN SOURCE FILES:")
    for f in sorted(own_files):
        lines.append(f"  {f}")

    lines.append("")
    lines.append("MODULE TREE:")
    lines.append("  src/")
    lines.append("  ├── main.rs              (entry point)")
    lines.append("  ├── consts.rs            (encrypted config: C2 URL, Sentry DSN, build info)")
    lines.append("  ├── utils.rs             (utility functions)")
    lines.append("  ├── browsers.rs          (browser enumeration)")
    lines.append("  ├── browsers/")
    lines.append("  │   └── chrome/")
    lines.append("  │       ├── modules.rs       (profile discovery)")
    lines.append("  │       └── modules/")
    lines.append("  │           ├── datas.rs      (SQL data extraction)")
    lines.append("  │           └── decryptors.rs (credential decryption)")
    lines.append("  └── pussy/")
    lines.append("      └── modules/")
    lines.append("          └── tg.rs         (Telegram session theft)")

    return '\n'.join(lines)


def extract_dependencies(data):
    """Extract Cargo crate dependencies from registry paths."""
    lines = ["CARGO DEPENDENCIES", "=" * 50, ""]
    pattern = re.compile(rb'/Users/rootr/\.cargo/registry/src/[^/]+/([a-zA-Z0-9_-]+-[\d.]+)')
    deps = sorted(set(m.group(1).decode() for m in pattern.finditer(data)))

    for dep in deps:
        # Split name and version
        parts = dep.rsplit('-', 1)
        if len(parts) == 2:
            lines.append(f"  {parts[0]:40s} v{parts[1]}")
        else:
            lines.append(f"  {dep}")

    lines.append(f"\nTotal: {len(deps)} crates")
    return '\n'.join(lines)


def extract_c2_protocol(data):
    """Document the C2 communication protocol."""
    lines = ["C2 COMMUNICATION PROTOCOL", "=" * 50, ""]

    lines.append("EXFILTRATION FIELDS:")
    lines.append("  log_id          - Unique log/victim identifier")
    lines.append("  ip              - Victim's IP address")
    lines.append("  geo             - Geolocation data")
    lines.append("  build_name      - Malware campaign name")
    lines.append("  build_version   - Malware variant version")
    lines.append("  pers_password   - Password from fake dialog (if entered)")
    lines.append("  passwords       - Stolen browser passwords")
    lines.append("  wallets         - Crypto wallet data")
    lines.append("  credits         - Stolen credit cards")
    lines.append("  autofills       - Browser autofill data")
    lines.append("  is_vm           - Virtual machine detection flag")
    lines.append("  hardwares       - System hardware info")
    lines.append("  force_mode      - Operational mode flag")
    lines.append("  uid             - Unique victim ID")
    lines.append("")
    lines.append("JSON KEYS (for HTTP POST):")
    lines.append("  buildName, buildVersion, uid")
    lines.append("")
    lines.append("UPLOAD:")
    lines.append("  Method:       HTTP POST multipart/form-data")
    lines.append("  Content-Type: application/zip")
    lines.append("  Protocol:     'UPLD connect'")
    lines.append("")
    lines.append("ERROR MESSAGES:")
    lines.append("  'Cannot connect to the server...'")
    lines.append("  'Please use VPN and retry.'")
    lines.append("  'ERROR ARC. TRYING AGAIN'")
    lines.append("  'Failed building the Runtime'")
    lines.append("")
    lines.append("DATA STAGING:")
    lines.append("  ~/Documents/temp_data/")
    lines.append("  ├── Keychain/Keychain.txt")
    lines.append("  ├── Cards.txt")
    lines.append("  ├── Tokens.txt")
    lines.append("  ├── Cookies/")
    lines.append("  ├── Apps/Telegram/")
    lines.append("  ├── Notes/")
    lines.append("  └── Application/")

    return '\n'.join(lines)


def extract_targets(data):
    """List all targeted applications and data."""
    lines = ["TARGETED APPLICATIONS & DATA", "=" * 50, ""]

    lines.append("BROWSERS (Chromium-based):")
    browsers = [
        ("Chrome",           "Google/Chrome",          "Chrome Safe Storage"),
        ("Brave",            "BraveSoftware/Brave-Browser", "Brave Safe Storage"),
        ("Opera",            "",                        "Opera Safe Storage"),
        ("Opera GX",         "",                        "Opera Safe Storage 2023"),
        ("Vivaldi",          "",                        "Vivaldi Safe Storage"),
        ("Microsoft Edge",   "",                        "Microsoft Edge Safe Storage"),
        ("Arc",              "Arc/User Data",           ""),
        ("CocCoc",           "",                        "CocCoc Safe Storage"),
    ]
    for name, path, keychain in browsers:
        lines.append(f"  {name:20s} path={path or 'default':30s} keychain='{keychain}'")

    lines.append("")
    lines.append("STOLEN BROWSER DATA:")
    lines.append("  - Passwords  (SELECT origin_url, username_value, password_value FROM logins)")
    lines.append("  - Credit cards (SELECT name_on_card, card_number_encrypted, ... FROM credit_cards)")
    lines.append("  - Cookies    (SELECT host_key, name, value, encrypted_value, ... FROM cookies)")
    lines.append("  - Autofill   (SELECT name, value FROM autofill)")
    lines.append("  - History    (SELECT title, url, visit_count FROM urls)")
    lines.append("  - Tokens     (SELECT service, encrypted_token FROM token_service)")

    lines.append("")
    lines.append("OTHER TARGETS:")
    lines.append("  - macOS Keychain  (login.keychain-db)")
    lines.append("  - Apple Notes     (via AppleScript/OSAKit)")
    lines.append("  - Telegram Desktop (/Library/Application Support/Telegram Desktop/tdata)")
    lines.append("    Subdirs: working, user_data, dumps, webview")

    # Search for crypto wallet references
    lines.append("")
    lines.append("CRYPTO WALLETS:")
    wallet_strings = re.findall(rb'[\x20-\x7e]*(?:Ledger|Trezor|MetaMask|Phantom|Exodus|Solflare|Coinbase)[\x20-\x7e]*', data, re.IGNORECASE)
    for ws in sorted(set(s.decode('ascii', errors='replace').strip() for s in wallet_strings)):
        if len(ws) > 3:
            lines.append(f"  - {ws}")

    if not wallet_strings:
        lines.append("  - Ledger Live (Live.app)")
        lines.append("  - Trezor Suite (Suite.app)")
        lines.append("  - Browser extension wallets (via /Local Extension Settings)")

    return '\n'.join(lines)


def extract_encrypted_config(data):
    """Hex dump the encrypted config block."""
    lines = ["ENCRYPTED CONFIG BLOCK (src/consts.rs)", "=" * 50, ""]

    consts_idx = data.find(b'src/consts.rs')
    if consts_idx == -1:
        return "src/consts.rs not found"

    enc_start = consts_idx + len(b'src/consts.rs')
    block = data[enc_start:enc_start + 256]

    lines.append(f"Offset in binary: {hex(enc_start)}")
    lines.append(f"Block size: {len(block)} bytes")
    lines.append("")

    for i in range(0, len(block), 16):
        row = block[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
        lines.append(f"{hex(enc_start + i)}: {hex_str:48s}  {asc}")

    lines.append("")
    lines.append("NOTES:")
    lines.append("  This block likely contains the encrypted Sentry DSN and C2 URL.")
    lines.append("  The encryption scheme is NOT simple XOR (verified).")
    lines.append("  Likely AES-CBC or custom Rust-based encryption.")
    lines.append("  Use Ghidra to decompile the init/config functions to find the key.")

    return '\n'.join(lines)


def extract_strings(data):
    """Comprehensive string extraction."""
    lines = ["ALL INTERESTING STRINGS", "=" * 50, ""]

    all_strings = sorted(set(s.decode('ascii', errors='replace')
                            for s in re.findall(rb'[\x20-\x7e]{6,}', data)))

    # Filter out noise (Rust stdlib, common library strings)
    noise_prefixes = ['/Users/rootr/.cargo', '/Users/rootr/.rustup',
                      'src/rust/library', 'assertion failed']

    interesting = [s for s in all_strings
                   if not any(s.startswith(p) for p in noise_prefixes)]

    for s in interesting:
        lines.append(s)

    return '\n'.join(lines)


def generate_iocs(data):
    """Generate IOC (Indicators of Compromise) package."""
    import hashlib

    content = SAMPLE.read_bytes()

    return {
        "malware_family": "Rust macOS Infostealer (pussy stealer variant)",
        "attribution": "Likely DPRK / Contagious Interview campaign",
        "hashes": {
            "sha256": hashlib.sha256(content).hexdigest(),
            "md5": hashlib.md5(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),
        },
        "file_info": {
            "type": "Mach-O universal binary (x86_64 + arm64)",
            "size_bytes": len(content),
            "compiler": "rustc 1.87.0 stable",
            "build_user": "rootr",
            "build_os": "macOS (Darwin)",
        },
        "infrastructure": {
            "delivery_domain": "macos.hyperhives.net",
            "delivery_url": "https://macos.hyperhives.net/install",
            "binary_url": "https://macos.hyperhives.net/installer",
            "email": "collabs@hyperhives.net",
            "registrar": "Tucows (via Tiered Access WHOIS)",
            "hosting": "Gcore CDN (81.28.12.12)",
            "github_account": "github.com/rootr (Geneva, zero repos)",
        },
        "capabilities": [
            "Browser password theft (Chrome, Brave, Opera, Edge, Vivaldi, Arc, CocCoc)",
            "Credit card extraction from browser databases",
            "Cookie theft",
            "Autofill data extraction",
            "Browser token theft",
            "macOS Keychain extraction",
            "Apple Notes exfiltration (via AppleScript)",
            "Telegram Desktop session theft",
            "Cryptocurrency wallet targeting",
            "VM detection",
            "Data staging to ~/Documents/temp_data/",
            "ZIP compression and HTTP exfiltration",
            "Sentry error tracking for reliability",
            "Gatekeeper bypass via xattr -c",
            "Fake password dialog via AppleScript",
        ],
        "mitre_attack": [
            "T1059.002 - AppleScript execution",
            "T1555.001 - Keychain credential access",
            "T1539 - Browser cookie theft",
            "T1005 - Data from local system",
            "T1560.002 - Archive collected data (ZIP)",
            "T1041 - Exfiltration over C2 channel",
            "T1497 - Virtualization/Sandbox evasion",
            "T1204.002 - User execution of malicious file",
        ],
    }


def dump_sections(data):
    """Dump Mach-O DATA sections."""
    try:
        import lief
        fat = lief.MachO.parse(str(SAMPLE))
        for binary in fat:
            for seg in binary.segments:
                if 'DATA' in seg.name or 'const' in seg.name.lower():
                    for sec in seg.sections:
                        if sec.size > 0 and sec.size < 1_000_000:
                            outfile = OUTPUT / f"section_{seg.name}_{sec.name}.bin"
                            outfile.write_bytes(bytes(sec.content))
    except ImportError:
        pass  # LIEF not available


def save(filename, content):
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / filename).write_text(content)
    print(f"  Saved: {filename}")


if __name__ == "__main__":
    main()
