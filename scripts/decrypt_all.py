#!/usr/bin/env python3
"""
DEFINITIVE CONFIG DECRYPTOR v2

Key insight: There are ~50+ different helper functions, not just 4.
They're ALL in the 0x10000-0x15000 code range and follow the same
pattern: ptr + hash16(seed). Instead of reverse-engineering each one,
we use Unicorn CPU emulation to execute the actual machine code.

Architecture:
  1. Scan binary for ALL RIP-relative LEAs to config region
  2. For each LEA, parse preceding code to find:
     - Helper CALL (target in 0x10000-0x15000 range)
     - Data pointer LEA (non-config address)
     - Seed MOV DWORD imm32
  3. Emulate helper function with Unicorn to get exact XOR offset
  4. Apply 32-byte XOR decryption
  5. Search for C2 URL, Sentry DSN, and attribute the attackers
"""

import struct, json, sys
from pathlib import Path
from collections import defaultdict, Counter

SAMPLE = Path("/lab/sample/installer_binary")
OUTPUT = Path("/lab/output")

CONFIG_MIN = 0x2b8000
CONFIG_MAX = 0x2bc000
HELPER_RANGE = (0x10000, 0x15000)
INFRA_CALLS = {0x19612, 0x9f0c, 0xdf48, 0xdf5d0, 0xd2ad, 0xaa1a5,
               0x288fe9, 0x292718, 0x75e80, 0x21b870, 0xb7c6, 0xb3ce,
               0xb9df, 0x442a, 0xdd41, 0x1cee01, 0x8db6, 0xb98a,
               0xc805, 0xc1b3, 0x8e49, 0xd9b7, 0x180a9, 0xda6e,
               0x50268, 0x9856, 0x3794, 0xd2db, 0xc928, 0x223870,
               0x223b20, 0x29290a, 0xdeda, 0xa7cb2}

def emulate_helper(data, func_offset, rdi_val, esi_val):
    """Execute a helper function via Unicorn and return rax."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UcError
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, \
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RAX, UC_X86_REG_RIP

    CODE_BASE = 0x10000
    STACK_BASE = 0x80000
    STOP_ADDR = CODE_BASE + 0x200

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_BASE, 0x10000, UC_PROT_ALL)
    mu.mem_map(STACK_BASE - 0x2000, 0x2000, UC_PROT_ALL)

    # Write function code at CODE_BASE
    func_code = data[func_offset:func_offset + 200]
    mu.mem_write(CODE_BASE, func_code)

    # Write HLT at stop address
    mu.mem_write(STOP_ADDR, b'\xf4')

    # Push return address to stack
    sp = STACK_BASE - 0x100
    mu.mem_write(sp, struct.pack('<Q', STOP_ADDR))

    mu.reg_write(UC_X86_REG_RSP, sp)
    mu.reg_write(UC_X86_REG_RBP, sp + 0x200)
    mu.reg_write(UC_X86_REG_RDI, rdi_val)
    mu.reg_write(UC_X86_REG_RSI, esi_val & 0xFFFFFFFFFFFFFFFF)

    try:
        mu.emu_start(CODE_BASE, STOP_ADDR, timeout=1000000, count=200)
    except UcError:
        pass

    return mu.reg_read(UC_X86_REG_RAX)


# Cache for helper results to avoid re-emulation
_helper_cache = {}

def cached_emulate(data, func_offset, data_ptr, seed):
    key = (func_offset, data_ptr, seed)
    if key not in _helper_cache:
        _helper_cache[key] = emulate_helper(data, func_offset, data_ptr, seed)
    return _helper_cache[key]


def scan_lea_refs(data, code_start, code_end):
    """Find all RIP-relative LEA instructions targeting the config region."""
    code = data[code_start:code_end]
    refs = defaultdict(list)

    i = 0
    while i < len(code) - 7:
        b0, b1 = code[i], code[i+1]
        if b0 in (0x48, 0x4C) and b1 == 0x8d:
            modrm = code[i+2]
            if (modrm >> 6) & 3 == 0 and modrm & 7 == 5:
                disp = struct.unpack('<i', code[i+3:i+7])[0]
                target = code_start + i + 7 + disp
                if CONFIG_MIN <= target <= CONFIG_MAX:
                    src = code_start + i
                    reg = ((modrm >> 3) & 7) + (8 if b0 == 0x4C else 0)
                    refs[target].append((src, reg))
                    i += 7
                    continue
        i += 1
    return refs


def find_decrypt_context(data, lea_addr, lookback=400):
    """Parse code before a config LEA to find (helper_call, data_ptr, seed)."""
    start = max(0, lea_addr - lookback)
    end = lea_addr

    # Find ALL calls in the lookback region
    helper_call = None
    helper_addr_in_code = None

    for i in range(end - 1, start - 1, -1):
        if i >= len(data) - 5:
            continue
        if data[i] == 0xE8:
            disp = struct.unpack('<i', data[i+1:i+5])[0]
            target = i + 5 + disp
            if HELPER_RANGE[0] <= target <= HELPER_RANGE[1]:
                helper_call = target
                helper_addr_in_code = i
                break

    if not helper_call:
        return None

    # Find data_ptr: LEA to non-config address, between helper call-80 and helper call
    data_ptr = None
    search_start = max(0, helper_addr_in_code - 100)
    for i in range(helper_addr_in_code - 1, search_start - 1, -1):
        if i >= len(data) - 7:
            continue
        if data[i] in (0x48, 0x4C) and data[i+1] == 0x8d:
            modrm = data[i+2]
            if (modrm >> 6) & 3 == 0 and modrm & 7 == 5:
                disp = struct.unpack('<i', data[i+3:i+7])[0]
                target = i + 7 + disp
                if not (CONFIG_MIN <= target <= CONFIG_MAX) and 0x1000 < target < len(data):
                    data_ptr = target
                    break

    if not data_ptr:
        return None

    # Find seed: MOV DWORD [reg], imm32 between data_ptr LEA and helper call
    seed = None
    for i in range(helper_addr_in_code - 1, search_start - 1, -1):
        if i >= len(data) - 6:
            continue
        if data[i] == 0xC7 and data[i+1] in (0x00, 0x01, 0x02, 0x03, 0x06, 0x07):
            imm = struct.unpack('<I', data[i+2:i+6])[0]
            if imm > 0x1000:
                seed = imm
                break

    if seed is None:
        return None

    # Find MOVABS (OR constant) between helper call and the config LEA
    or_const = None
    for i in range(helper_addr_in_code, min(lea_addr + 20, len(data) - 10)):
        if data[i] == 0x48 and 0xb8 <= data[i+1] <= 0xbf:
            imm64 = struct.unpack('<Q', data[i+2:i+10])[0]
            if imm64 > 0xFFFFFFFF:
                or_const = imm64
                break

    return {
        'helper_offset': helper_call,
        'data_ptr': data_ptr,
        'seed': seed,
        'or_const': or_const,
        'call_addr': helper_addr_in_code,
    }


def main():
    data = SAMPLE.read_bytes()
    binary_len = len(data)

    print("=" * 70)
    print("DEFINITIVE CONFIG DECRYPTOR v2 (Unicorn-powered)")
    print("=" * 70)

    # ─── Step 1: Scan for all LEA refs ────────────────────────────────
    code_start, code_end = 0x12e0, 0x2905b0
    print(f"\n[1] Scanning code for config references...")
    refs = scan_lea_refs(data, code_start, code_end)
    total = sum(len(v) for v in refs.values())
    print(f"  {total} refs to {len(refs)} unique addresses")

    # ─── Step 2: Extract decrypt context for each ref ─────────────────
    print(f"\n[2] Extracting decryption parameters...")

    contexts = {}
    found = 0
    missed = 0

    for enc_addr in sorted(refs.keys()):
        for src_addr, dest_reg in refs[enc_addr]:
            ctx = find_decrypt_context(data, src_addr)
            if ctx:
                ctx['dest_reg'] = dest_reg
                ctx['src_addr'] = src_addr
                if enc_addr not in contexts:
                    contexts[enc_addr] = ctx
                    found += 1
                break
        else:
            missed += 1

    print(f"  Found context for {found}/{found+missed} addresses")

    # Count unique helpers
    unique_helpers = Counter(c['helper_offset'] for c in contexts.values())
    print(f"  {len(unique_helpers)} unique helper functions found")
    for h, cnt in unique_helpers.most_common(10):
        print(f"    0x{h:05x}: {cnt} uses")

    # ─── Step 3: Emulate helpers and decrypt ──────────────────────────
    print(f"\n[3] Emulating helpers and decrypting ({found} blocks)...")

    decrypted = {}
    or_xor_results = {}
    errors = 0

    for enc_addr in sorted(contexts.keys()):
        ctx = contexts[enc_addr]
        try:
            xor_offset = cached_emulate(
                data, ctx['helper_offset'], ctx['data_ptr'], ctx['seed'])

            # The emulated function returns data_ptr + offset
            # But we emulated with the FILE offset as rdi, so the result
            # is also a file offset (since the function does rdi + hash16)
            if xor_offset < 0 or xor_offset + 32 > binary_len:
                errors += 1
                continue

            # Determine decrypt type by register
            dest_reg = ctx['dest_reg']

            if ctx.get('or_const') and dest_reg in (1, 9):  # rcx / r9
                # OR+XOR pattern
                or_c = ctx['or_const']
                xor_data = data[xor_offset:xor_offset + 16]
                if len(xor_data) >= 16:
                    enc_b0 = data[enc_addr]
                    r0 = struct.pack('<Q', (enc_b0 | or_c) ^
                                     struct.unpack('<Q', xor_data[0:8])[0])

                    enc_b8 = data[enc_addr + 8] if enc_addr + 8 < binary_len else 0
                    r8 = struct.pack('<Q', (enc_b8 | or_c) ^
                                     struct.unpack('<Q', xor_data[8:16])[0])

                    text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in r0 + r8)
                    or_xor_results[enc_addr] = text
            else:
                # 32-byte XOR
                enc = data[enc_addr:enc_addr + 32]
                key = data[xor_offset:xor_offset + 32]
                if len(enc) == 32 and len(key) == 32:
                    dec = bytes(enc[i] ^ key[i] for i in range(32))
                    printable = sum(1 for b in dec if 32 <= b < 127)
                    if printable >= 8:
                        text = dec.decode('ascii', errors='replace')
                        clean = ''.join(c if 32 <= ord(c) < 127 else '' for c in text)
                        decrypted[enc_addr] = clean

        except Exception as e:
            errors += 1

    print(f"  Decrypted {len(decrypted)} blocks, {len(or_xor_results)} OR+XOR values, {errors} errors")

    # ─── Step 4: Report results ──────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"DECRYPTED CONFIG STRINGS ({len(decrypted)})")
    print(f"{'='*70}")

    all_strings = []
    for addr in sorted(decrypted.keys()):
        text = decrypted[addr]
        if len(text) >= 3:
            all_strings.append((addr, text))
            print(f"  0x{addr:06x}: {text}")

    # ─── Step 5: Hunt for C2 URL and Sentry DSN ─────────────────────
    print(f"\n{'='*70}")
    print("C2 URL / SENTRY DSN / ATTRIBUTION")
    print(f"{'='*70}")

    for addr, text in all_strings:
        tl = text.lower()
        if any(p in tl for p in ['http', '://', 'sentry', '.io', '.com', '.net',
                                   'ingest', '@', 'dsn']):
            print(f"  *** MATCH at 0x{addr:06x}: {text}")

    # Look for multi-block URLs (adjacent blocks forming a URL)
    print(f"\n  Checking consecutive blocks for multi-block strings...")
    sorted_items = sorted(all_strings)
    for i in range(len(sorted_items) - 1):
        addr1, text1 = sorted_items[i]
        addr2, text2 = sorted_items[i + 1]
        if addr2 - addr1 <= 33:
            combined = text1 + text2
            if any(p in combined.lower() for p in ['http', 'sentry', '@', '://']):
                print(f"  *** COMBINED: 0x{addr1:06x}+0x{addr2:06x}: {combined}")

    # ─── Step 6: Categorize ──────────────────────────────────────────
    print(f"\n{'='*70}")
    print("CATEGORIZED FINDINGS")
    print(f"{'='*70}")

    wallets, ext_ids, urls, sentry_vals, browsers, paths, other = \
        [], [], [], [], [], [], []

    wallet_names = {'wallet', 'metamask', 'nifty', 'trust', 'ronin', 'terra',
                    'phantom', 'solflare', 'math', 'equal', 'wombat', 'saturn',
                    'kardia', 'oxygen', 'liquality', 'xdefi', 'martian', 'rise',
                    'maiar', 'nami', 'multiverse', 'leo', 'sui', 'fetch',
                    'ambire', 'jaxxx', 'liberty'}

    for addr, text in all_strings:
        tl = text.lower()
        is_ext_id = (len(text) >= 30 and
                     all(c in 'abcdefghijklmnop' for c in text if c.isalpha()))

        if is_ext_id:
            ext_ids.append(text)
        elif any(w in tl for w in wallet_names):
            wallets.append(text)
        elif 'http' in tl or '://' in tl:
            urls.append(text)
        elif 'sentry' in tl or 'dsn' in tl:
            sentry_vals.append(text)
        elif any(p in tl for p in ['chrome', 'brave', 'opera', 'edge', 'firefox',
                                    'browser', 'cookie', 'login', 'password']):
            browsers.append(text)
        elif '/' in text and len(text) > 10:
            paths.append(text)
        else:
            other.append((addr, text))

    for category, items in [("Wallets", wallets), ("Extension IDs", ext_ids),
                             ("URLs", urls), ("Sentry", sentry_vals),
                             ("Browser targets", browsers), ("Paths", paths)]:
        if items:
            print(f"\n  {category} ({len(items)}):")
            for item in items:
                print(f"    {item}")

    if other:
        print(f"\n  Other ({len(other)}):")
        for addr, text in other[:80]:
            print(f"    0x{addr:06x}: {text}")

    # ─── Step 7: OR+XOR values ───────────────────────────────────────
    if or_xor_results:
        print(f"\n  OR+XOR decoded ({len(or_xor_results)}):")
        for addr in sorted(or_xor_results.keys()):
            text = or_xor_results[addr]
            if sum(1 for c in text if c != '.') >= 3:
                print(f"    0x{addr:06x}: {text}")

    # ─── Save ────────────────────────────────────────────────────────
    results = {
        "total_decrypted": len(decrypted),
        "wallets": wallets,
        "extension_ids": ext_ids,
        "urls": urls,
        "sentry": sentry_vals,
        "browsers": browsers,
        "paths": paths,
        "other": {hex(a): t for a, t in other},
        "all_strings": {hex(a): t for a, t in all_strings},
        "or_xor": or_xor_results,
    }

    with open(OUTPUT / "full_decrypted_config.json", 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n  Saved to output/full_decrypted_config.json")
    print(f"\n  TOTAL: {len(decrypted)} XOR blocks + {len(or_xor_results)} OR+XOR = "
          f"{len(decrypted) + len(or_xor_results)} config values decrypted")

if __name__ == "__main__":
    main()
