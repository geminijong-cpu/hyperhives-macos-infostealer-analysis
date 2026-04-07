#!/usr/bin/env python3
"""
Radare2-based analysis of the malware binary.
Extracts disassembly of key functions, cross-references,
and attempts to trace the C2 URL decryption logic.

Usage (inside container):
    python3 /lab/scripts/r2_analyze.py
"""

import r2pipe
import json
import re
from pathlib import Path

SAMPLE = "/lab/sample/installer_binary"
OUTPUT = Path("/lab/output/r2")

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("RADARE2 ANALYSIS")
    print("=" * 60)

    # Open binary in radare2
    r2 = r2pipe.open(SAMPLE, flags=["-2"])  # -2 = no stderr

    print("\nAnalyzing binary (this takes a minute)...")
    r2.cmd("aaa")  # Full analysis

    # 1. Binary info
    print("\n--- Binary Info ---")
    info = json.loads(r2.cmd("ij"))
    print(f"  Format: {info['bin']['class']}")
    print(f"  Arch: {info['bin']['arch']}")
    print(f"  Bits: {info['bin']['bits']}")
    print(f"  Compiler: {info['bin'].get('compiler', 'unknown')}")

    # 2. Find all functions
    functions = json.loads(r2.cmd("aflj"))
    print(f"\n--- Functions: {len(functions)} total ---")

    # Filter to app-level functions
    interesting_keywords = ['main', 'consts', 'pussy', 'browser', 'chrome',
                           'decrypt', 'keychain', 'telegram', 'upload',
                           'config', 'sentry', 'send', 'connect', 'http',
                           'init', 'steal', 'grab', 'collect', 'xor',
                           'aes', 'encrypt', 'key', 'dsn']

    app_funcs = []
    for f in functions:
        name = f.get('name', '').lower()
        if any(k in name for k in interesting_keywords):
            app_funcs.append(f)

    print(f"  Application-relevant: {len(app_funcs)}")
    for f in app_funcs[:30]:
        print(f"    {f['offset']:#x}: {f['name']} (size={f.get('size', '?')})")

    # 3. Disassemble key functions
    print("\n--- Disassembling key functions ---")
    for f in app_funcs[:20]:
        fname = f['name']
        addr = f['offset']
        size = f.get('size', 100)

        disasm = r2.cmd(f"pdf @ {addr}")
        if disasm:
            outfile = OUTPUT / f"{fname.replace('/', '_')}.asm"
            outfile.write_text(f"// Function: {fname}\n// Address: {addr:#x}\n\n{disasm}")
            print(f"  Saved: {outfile.name}")

    # 4. Search for string references to encryption-related content
    print("\n--- Cross-references to crypto strings ---")
    for search_str in ['sentry', 'DSN', 'consts', 'https', 'decrypt']:
        results = r2.cmd(f"/ {search_str}")
        if results.strip():
            print(f"\n  References to '{search_str}':")
            for line in results.strip().split('\n')[:5]:
                print(f"    {line}")
                # Get xrefs to this address
                addr_match = re.search(r'0x([0-9a-f]+)', line)
                if addr_match:
                    addr = addr_match.group(0)
                    xrefs = r2.cmd(f"axt @ {addr}")
                    if xrefs.strip():
                        for xref in xrefs.strip().split('\n')[:3]:
                            print(f"      xref: {xref}")

    # 5. Look at the main function
    print("\n--- Main function ---")
    main_addr = None
    for f in functions:
        if f.get('name', '') in ['main', 'sym.main', 'entry0', '_main']:
            main_addr = f['offset']
            break

    if main_addr:
        main_disasm = r2.cmd(f"pdf @ {main_addr}")
        (OUTPUT / "main.asm").write_text(main_disasm or "")
        print(f"  Main at {main_addr:#x}, saved to main.asm")
        # Show calls from main
        calls = [l for l in (main_disasm or '').split('\n') if 'call' in l.lower()]
        print(f"  Calls from main ({len(calls)}):")
        for c in calls[:15]:
            print(f"    {c.strip()}")

    # 6. Data section dump
    print("\n--- Data sections ---")
    sections = json.loads(r2.cmd("iSj"))
    for sec in sections:
        if 'data' in sec.get('name', '').lower() or 'const' in sec.get('name', '').lower():
            print(f"  {sec['name']}: offset={sec.get('paddr', '?'):#x} "
                  f"size={sec.get('size', '?'):#x}")

    r2.quit()

    print(f"\nAll output saved to: {OUTPUT}/")
    print("Open the .asm files in your IDE to review disassembly.")

if __name__ == "__main__":
    main()
