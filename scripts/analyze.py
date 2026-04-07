#!/usr/bin/env python3
"""
Static analysis toolkit for the HyperHives macOS infostealer.
Run inside the Docker container only.

Usage:
    python3 /lab/scripts/analyze.py [command]

Commands:
    info        - Basic binary info (architectures, sections, imports)
    strings     - Extract and categorize interesting strings
    symbols     - Dump and demangle Rust symbols
    crypto      - Search for encryption keys, encoded configs, Sentry DSN
    c2          - Attempt to extract C2 server URL
    exports     - Extract all function exports
    full        - Run all analyses
"""

import sys
import os
import re
import struct
import json
from pathlib import Path

SAMPLE = Path("/lab/sample/installer_binary")
OUTPUT = Path("/lab/output")

def ensure_output():
    OUTPUT.mkdir(parents=True, exist_ok=True)

def load_binary():
    return SAMPLE.read_bytes()

# ─── INFO ───────────────────────────────────────────────────────────────

def cmd_info():
    """Basic binary metadata using LIEF."""
    import lief
    print("=" * 60)
    print("BINARY INFO")
    print("=" * 60)

    fat = lief.MachO.parse(str(SAMPLE))
    for i, binary in enumerate(fat):
        arch = binary.header.cpu_type.name
        print(f"\n--- Slice {i}: {arch} ---")
        print(f"  File type : {binary.header.file_type.name}")
        print(f"  Flags     : {binary.header.flags_list}")
        print(f"  Segments  :")
        for seg in binary.segments:
            print(f"    {seg.name:20s} offset={hex(seg.file_offset):>10s} "
                  f"size={hex(seg.file_size):>10s} vm={hex(seg.virtual_address):>14s}")
            for sec in seg.sections:
                print(f"      {sec.name:20s} offset={hex(sec.offset):>10s} "
                      f"size={hex(sec.size):>10s}")

        print(f"  Libraries :")
        for lib in binary.libraries:
            print(f"    {lib.name}")

        print(f"\n  Imports ({len(list(binary.imported_symbols))} total):")
        imports = [s.name for s in binary.imported_symbols]
        # Show interesting ones
        interesting = [s for s in imports if any(k in s.lower() for k in
                       ['security', 'keychain', 'sqlite', 'osakit', 'script',
                        'pasteboard', 'credential', 'crypto', 'ssl'])]
        for s in interesting[:50]:
            print(f"    {s}")

    results = {"slices": len(list(fat)), "sample": str(SAMPLE)}
    save_json("info.json", results)


# ─── STRINGS ────────────────────────────────────────────────────────────

def cmd_strings():
    """Extract and categorize interesting strings."""
    data = load_binary()
    all_strings = re.findall(rb'[\x20-\x7e]{5,}', data)
    decoded = [s.decode('ascii', errors='replace') for s in all_strings]

    categories = {
        "urls": [],
        "paths": [],
        "sql_queries": [],
        "crypto_wallet": [],
        "browser_targets": [],
        "c2_protocol": [],
        "sentry": [],
        "source_files": [],
        "error_messages": [],
        "credentials": [],
    }

    for s in decoded:
        sl = s.lower()
        if 'http' in sl or '://' in sl:
            categories["urls"].append(s)
        if 'select ' in sl and ' from ' in sl:
            categories["sql_queries"].append(s)
        if any(w in sl for w in ['wallet', 'ledger', 'trezor', 'metamask', 'phantom', 'solflare', 'exodus', 'bitcoin', 'ethereum']):
            categories["crypto_wallet"].append(s)
        if any(w in sl for w in ['chrome', 'brave', 'opera', 'firefox', 'safari', 'edge', 'vivaldi', 'arc', 'coccoc']):
            categories["browser_targets"].append(s)
        if any(w in sl for w in ['build_name', 'log_id', 'pers_password', 'force_mode', 'upld', 'hardwares', 'is_vm']):
            categories["c2_protocol"].append(s)
        if 'sentry' in sl or 'dsn' in sl.split('/'):
            categories["sentry"].append(s)
        if s.startswith('src/') and s.endswith('.rs'):
            categories["source_files"].append(s)
        if any(w in sl for w in ['keychain', 'password', 'credential', 'login data', 'safe storage', 'token']):
            categories["credentials"].append(s)
        if s.startswith('/Users/') or s.startswith('/Documents/') or s.startswith('/Library/'):
            categories["paths"].append(s)

    print("=" * 60)
    print("CATEGORIZED STRINGS")
    print("=" * 60)

    for cat, items in categories.items():
        unique = sorted(set(items))
        if unique:
            print(f"\n--- {cat.upper()} ({len(unique)} unique) ---")
            for item in unique[:50]:
                print(f"  {item}")

    # Save full results
    save_json("strings.json", {k: sorted(set(v)) for k, v in categories.items()})
    print(f"\nFull results saved to {OUTPUT}/strings.json")


# ─── SYMBOLS ────────────────────────────────────────────────────────────

def cmd_symbols():
    """Dump and demangle Rust symbols."""
    import lief
    import subprocess

    print("=" * 60)
    print("RUST SYMBOLS (demangled)")
    print("=" * 60)

    fat = lief.MachO.parse(str(SAMPLE))
    binary = list(fat)[0]  # Use first slice

    symbols = []
    for sym in binary.symbols:
        name = sym.name
        if name and not name.startswith('_$'):
            symbols.append(name)

    # Demangle through rustfilt
    raw = '\n'.join(symbols)
    try:
        result = subprocess.run(['rustfilt'], input=raw, capture_output=True, text=True, timeout=30)
        demangled = result.stdout.strip().split('\n')
    except (FileNotFoundError, subprocess.TimeoutExpired):
        demangled = symbols

    # Filter to interesting application-level symbols
    app_symbols = [s for s in demangled if any(k in s for k in
                   ['main', 'consts', 'pussy', 'browser', 'chrome', 'decrypt',
                    'keychain', 'telegram', 'upload', 'steal', 'grab', 'exfil',
                    'config', 'c2', 'server', 'sentry', 'send', 'collect'])]

    print(f"\nTotal symbols: {len(symbols)}")
    print(f"Application-relevant symbols: {len(app_symbols)}")
    for s in sorted(set(app_symbols)):
        print(f"  {s}")

    save_json("symbols.json", {"total": len(symbols), "app_relevant": sorted(set(app_symbols))})


# ─── CRYPTO / CONFIG EXTRACTION ────────────────────────────────────────

def cmd_crypto():
    """Search for encryption keys, encoded configs, Sentry DSN."""
    data = load_binary()

    print("=" * 60)
    print("CRYPTO & CONFIG ANALYSIS")
    print("=" * 60)

    # 1. Find the encrypted config block after src/consts.rs
    consts_idx = data.find(b'src/consts.rs')
    if consts_idx == -1:
        print("WARNING: src/consts.rs not found in binary")
        return

    print(f"\nsrc/consts.rs reference at: {hex(consts_idx)}")

    # The encrypted blob starts right after the filename
    enc_start = consts_idx + len(b'src/consts.rs')
    enc_block = data[enc_start:enc_start + 256]

    print(f"\nEncrypted config block ({hex(enc_start)}):")
    for i in range(0, min(256, len(enc_block)), 16):
        hex_str = ' '.join(f'{b:02x}' for b in enc_block[i:i+16])
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in enc_block[i:i+16])
        print(f"  {hex(enc_start + i)}: {hex_str:48s}  {asc}")

    # 2. Multi-byte XOR brute force with known plaintext "https://"
    print("\n--- Multi-byte XOR with known plaintext 'https://' ---")
    known = b"https://"
    for offset in range(0, 32):
        candidate = data[enc_start + offset:enc_start + offset + 8]
        if len(candidate) < 8:
            continue
        key = bytes(a ^ b for a, b in zip(candidate, known))

        # Try decrypting with this key (repeating)
        dec = bytearray()
        for i in range(128):
            idx = enc_start + offset + i
            if idx < len(data):
                dec.append(data[idx] ^ key[i % len(key)])
        dec_str = dec.decode('ascii', errors='replace')

        # Score: count printable ASCII ratio
        printable = sum(1 for c in dec if 32 <= c < 127)
        ratio = printable / len(dec) if dec else 0

        if ratio > 0.7 and ('.' in dec_str[8:30]):
            print(f"  offset +{offset}: key={key.hex()} ratio={ratio:.2f}")
            print(f"  decrypted: {dec_str[:120]}")

    # 3. Search for AES keys (16/24/32 byte high-entropy blocks near crypto code)
    print("\n--- Potential AES key candidates ---")
    # Look near hmac/aes/cipher references
    for marker in [b'saltysalt', b'Safe Storage', b'hmac']:
        idx = data.find(marker)
        if idx != -1:
            # Check 256 bytes before and after for high-entropy 16/32 byte blocks
            region = data[max(0, idx-256):idx+256]
            for klen in [16, 32]:
                for i in range(len(region) - klen):
                    block = region[i:i+klen]
                    entropy = len(set(block)) / klen
                    if entropy > 0.85:
                        print(f"  Near '{marker.decode()}' +{i-256}: "
                              f"entropy={entropy:.2f} hex={block.hex()[:64]}...")

    # 4. Search entire binary for Sentry DSN format
    print("\n--- Sentry DSN search ---")
    # Look for the @ symbol surrounded by hex chars (DSN key format)
    dsn_pattern = re.compile(rb'[0-9a-f]{16,64}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+')
    for match in dsn_pattern.finditer(data):
        print(f"  FOUND DSN: {match.group().decode()}")

    # 5. Look for reversed strings
    print("\n--- Reversed string check ---")
    for target in [b'https://', b'sentry', b'.ingest.', b'api.telegram']:
        reversed_target = target[::-1]
        idx = data.find(reversed_target)
        if idx != -1:
            context = data[idx:idx+100]
            print(f"  Reversed '{target.decode()}' found at {hex(idx)}: {context[:60]}")

    save_json("crypto_analysis.json", {
        "consts_offset": hex(consts_idx),
        "enc_block_hex": enc_block[:128].hex(),
    })


# ─── C2 EXTRACTION ─────────────────────────────────────────────────────

def cmd_c2():
    """Attempt to extract the C2 server URL using multiple techniques."""
    data = load_binary()

    print("=" * 60)
    print("C2 EXTRACTION ATTEMPTS")
    print("=" * 60)

    # 1. Full binary XOR scan for any encoded URL
    print("\n--- Full binary XOR scan (all single-byte keys) ---")
    for key in range(1, 256):
        target = bytes(b ^ key for b in b"https://")
        idx = 0
        while True:
            idx = data.find(target, idx)
            if idx == -1:
                break
            dec = bytes(data[idx + i] ^ key for i in range(min(120, len(data) - idx)))
            dec_str = dec.decode('ascii', errors='replace')
            if '.' in dec_str[8:40] and re.match(r'https://[\w.-]+', dec_str):
                print(f"  Key=0x{key:02x} at {hex(idx)}: {dec_str[:100]}")
            idx += 1

    # 2. Multi-byte XOR (2-16 byte keys) on likely config regions
    print("\n--- Multi-byte XOR on config regions ---")
    consts_idx = data.find(b'src/consts.rs')
    if consts_idx != -1:
        region = data[consts_idx:consts_idx + 512]
        known = b"https://"
        for key_len in range(2, 17):
            for start in range(len(region) - 8):
                candidate = region[start:start + 8]
                key_fragment = bytes(a ^ b for a, b in zip(candidate, known))
                # Extend key by repeating pattern
                full_key = (key_fragment[:key_len]) * ((128 // key_len) + 1)
                dec = bytes(region[start + i] ^ full_key[i] for i in range(min(128, len(region) - start)))
                dec_str = dec.decode('ascii', errors='replace')
                printable = sum(1 for c in dec if 32 <= c < 127)
                if printable / len(dec) > 0.8 and 'sentry' in dec_str.lower():
                    print(f"  KEY FOUND! len={key_len} offset=+{start}: {dec_str[:100]}")

    # 3. RC4 with common keys
    print("\n--- RC4 with common keys ---")
    def rc4(key, data):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(result)

    # Try RC4 with keys found in the binary
    potential_keys = [b'wOcR3t;}~c\'', b'saltysalt', b'HyperHives', b'hyperhives',
                      b'installer', b'rootr', b'RootR', b'pussy']
    if consts_idx != -1:
        enc_region = data[consts_idx + 13:consts_idx + 200]
        for key in potential_keys:
            dec = rc4(key, enc_region)
            dec_str = dec.decode('ascii', errors='replace')
            printable = sum(1 for c in dec if 32 <= c < 127)
            if printable / len(dec) > 0.6:
                print(f"  RC4 key '{key.decode(errors='replace')}': {dec_str[:100]}")

    # 4. Check for XOR with build constants
    print("\n--- XOR with binary-embedded constants ---")
    # Extract all short printable strings from consts region as potential keys
    if consts_idx != -1:
        nearby = data[consts_idx - 1000:consts_idx + 1000]
        short_strings = re.findall(rb'[\x20-\x7e]{3,20}', nearby)
        enc_block = data[consts_idx + 13:consts_idx + 200]
        for key_str in short_strings:
            dec = bytearray()
            for i in range(min(80, len(enc_block))):
                dec.append(enc_block[i] ^ key_str[i % len(key_str)])
            dec_text = dec.decode('ascii', errors='replace')
            if 'http' in dec_text[:10]:
                print(f"  XOR key '{key_str.decode(errors='replace')}': {dec_text[:100]}")

    print("\nNote: If no C2 found, the URL is likely AES-encrypted or")
    print("constructed at runtime via string concatenation.")
    print("Use Ghidra decompilation for definitive extraction:")
    print("  python3 /lab/scripts/ghidra_decompile.py")


# ─── UTILITIES ──────────────────────────────────────────────────────────

def save_json(filename, data):
    ensure_output()
    path = OUTPUT / filename
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def cmd_full():
    """Run all analysis commands."""
    for cmd in [cmd_info, cmd_strings, cmd_symbols, cmd_crypto, cmd_c2]:
        try:
            cmd()
        except Exception as e:
            print(f"\nERROR in {cmd.__name__}: {e}")
        print()

# ─── MAIN ───────────────────────────────────────────────────────────────

COMMANDS = {
    "info": cmd_info,
    "strings": cmd_strings,
    "symbols": cmd_symbols,
    "crypto": cmd_crypto,
    "c2": cmd_c2,
    "full": cmd_full,
}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "full"
    if cmd in COMMANDS:
        COMMANDS[cmd]()
    else:
        print(__doc__)
        print(f"Available commands: {', '.join(COMMANDS.keys())}")
