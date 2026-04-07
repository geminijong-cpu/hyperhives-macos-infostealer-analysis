#!/usr/bin/env python3
"""
Targeted r2 analysis - skip full analysis, just disassemble at specific offsets.
Focus on the x86_64 slice since instructions are easier to read.
"""

import r2pipe
import re
import struct
from pathlib import Path

SAMPLE = "/lab/sample/installer_binary"
OUTPUT = Path("/lab/output/r2_targeted")

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    
    # Open with x86_64 analysis, skip auto-analysis
    r2 = r2pipe.open(SAMPLE, flags=["-2", "-a", "x86", "-b", "64"])
    
    # Don't run aaa - too slow. Just do minimal setup.
    r2.cmd("e analysis.arch=x86")
    r2.cmd("e analysis.bits=64")
    
    print("=" * 70)
    print("TARGETED R2 ANALYSIS (no full analysis)")
    print("=" * 70)
    
    # Key addresses (x86_64 slice):
    # src/consts.rs at 0x2b85a8
    # encrypted data starts at 0x2b85b5
    # buildName at 0x2bbac2
    # "enabled sentry client for DSN" at 0x2b769c
    # "UPLD connect" at 0x2bba1c
    # 32-byte pre-key at 0x2b8588
    
    # ─── 1. Find code refs to the encrypted data region ───────────────
    print("\n[1] FINDING CODE REFS TO ENCRYPTED DATA REGION")
    print("-" * 50)
    
    # The x86_64 TEXT section starts at 0x12e0 and is 0x28f2d0 bytes
    # So code range is 0x12e0 to 0x2905b0
    
    # Search for references to the encrypted data address
    # In x86_64, the binary is position-dependent with base 0x100000000
    # So the virtual address of 0x2b85b5 is 0x1002b85b5
    
    enc_vaddr = 0x1002b85b5
    consts_vaddr = 0x1002b85a8
    
    # Search for lea/mov instructions that load this address
    # In x86_64, LEA rax, [rip + offset] is common
    # The offset = target - (current_addr + instr_len)
    
    # Alternative: search for the immediate bytes of the address
    # Little-endian representation of key parts of the address
    enc_bytes_le = struct.pack('<I', enc_vaddr & 0xFFFFFFFF)  # Lower 32 bits
    
    print(f"  Searching for references to {hex(enc_vaddr)}...")
    
    # Search within the code section
    code_start = 0x12e0
    code_end = 0x2905b0
    
    # Read code section
    code_hex = r2.cmd(f"p8 {code_end - code_start} @ {code_start}")
    if code_hex:
        code_bytes = bytes.fromhex(code_hex.strip())
        
        # Search for the lower 32 bits of the vaddr
        target_patterns = [
            enc_bytes_le,
            struct.pack('<I', consts_vaddr & 0xFFFFFFFF),
            struct.pack('<I', 0x2b85b5),  # file offset
            struct.pack('<I', 0x2b85a8),  # consts.rs file offset
            struct.pack('<I', 0x2b8588),  # pre-key file offset
        ]
        
        for pattern in target_patterns:
            idx = 0
            count = 0
            while count < 20:
                idx = code_bytes.find(pattern, idx)
                if idx == -1:
                    break
                abs_off = code_start + idx
                # Disassemble around this location
                disasm = r2.cmd(f"pd 10 @ {abs_off - 8}")
                print(f"\n  Pattern {pattern.hex()} found at {hex(abs_off)}:")
                for line in disasm.strip().split('\n')[:10]:
                    print(f"    {line}")
                idx += 1
                count += 1
    
    # ─── 2. Search for RIP-relative references ───────────────────────
    print("\n\n[2] SEARCHING FOR RIP-RELATIVE REFERENCES TO CONFIG")
    print("-" * 50)
    
    # In x86_64, lea rax, [rip+disp32] encodes as: 48 8d 05 XX XX XX XX
    # where disp32 = target - (current_ip + 7)
    # Let's search for any instruction that references addresses near
    # our encrypted data (0x2b8580 - 0x2b85c0)
    
    target_range_start = 0x2b8580  # file offsets of interest
    target_range_end = 0x2b85c0
    
    lea_pattern = bytes([0x48, 0x8d])  # lea r64, [rip+...]
    
    hits_found = []
    idx = 0
    while idx < len(code_bytes) - 7:
        # Look for 48 8d XX (where XX has mod=00, rm=101 for RIP-relative)
        if code_bytes[idx] == 0x48 and code_bytes[idx + 1] == 0x8d:
            modrm = code_bytes[idx + 2]
            mod_field = (modrm >> 6) & 3
            rm_field = modrm & 7
            
            if mod_field == 0 and rm_field == 5:  # RIP-relative
                disp32 = struct.unpack('<i', code_bytes[idx + 3:idx + 7])[0]
                current_ip = code_start + idx + 7
                target = current_ip + disp32
                
                if target_range_start <= target <= target_range_end + 2048:
                    abs_off = code_start + idx
                    disasm = r2.cmd(f"pd 15 @ {abs_off - 16}")
                    print(f"\n  LEA RIP-relative to {hex(target)} from {hex(abs_off)}:")
                    for line in disasm.strip().split('\n')[:15]:
                        print(f"    {line}")
                    hits_found.append(abs_off)
        idx += 1
    
    # ─── 3. Disassemble the main function ─────────────────────────────
    print("\n\n[3] MAIN FUNCTION (x86_64)")
    print("-" * 50)
    
    # Find _main symbol - search for the entry point
    entry = r2.cmd("ie~vaddr").strip()
    print(f"  Entry point: {entry}")
    
    # The entry typically calls main. Let's disassemble from entry.
    entry_disasm = r2.cmd("pd 50 @ entry0")
    print(f"  Entry disassembly:")
    for line in entry_disasm.strip().split('\n')[:20]:
        print(f"    {line}")
    
    # ─── 4. Search for the Sentry DSN initialization ──────────────────
    print("\n\n[4] SENTRY DSN INIT REFERENCES")
    print("-" * 50)
    
    # The string "enabled sentry client for DSN" is at 0x2b769c
    # Find RIP-relative refs to this string
    sentry_str_offset = 0x2b769c
    
    idx = 0
    while idx < len(code_bytes) - 7:
        if code_bytes[idx] == 0x48 and code_bytes[idx + 1] == 0x8d:
            modrm = code_bytes[idx + 2]
            if (modrm >> 6) & 3 == 0 and modrm & 7 == 5:
                disp32 = struct.unpack('<i', code_bytes[idx + 3:idx + 7])[0]
                current_ip = code_start + idx + 7
                target = current_ip + disp32
                
                if abs(target - sentry_str_offset) < 100:
                    abs_off = code_start + idx
                    # Found! Disassemble a large chunk of the containing function
                    disasm = r2.cmd(f"pd 100 @ {abs_off - 64}")
                    print(f"\n  Ref to sentry DSN string from {hex(abs_off)}:")
                    (OUTPUT / f"sentry_dsn_ref_{abs_off:#x}.asm").write_text(disasm)
                    for line in disasm.strip().split('\n')[:40]:
                        print(f"    {line}")
        idx += 1
    
    # ─── 5. Search for AES-related patterns in code ───────────────────
    print("\n\n[5] AES CODE PATTERNS")
    print("-" * 50)
    
    # AESNI instructions: 66 0f 38 dc (aesenc), 66 0f 38 dd (aesenclast)
    # 66 0f 38 de (aesdec), 66 0f 38 df (aesdeclast)
    aes_opcodes = {
        b'\x66\x0f\x38\xdc': 'AESENC',
        b'\x66\x0f\x38\xdd': 'AESENCLAST',
        b'\x66\x0f\x38\xde': 'AESDEC',
        b'\x66\x0f\x38\xdf': 'AESDECLAST',
        b'\x66\x0f\x38\xdb': 'AESIMC',
        b'\x66\x0f\x3a\xdf': 'AESKEYGENASSIST',
    }
    
    for opcode, name in aes_opcodes.items():
        idx = 0
        count = 0
        while count < 10:
            idx = code_bytes.find(opcode, idx)
            if idx == -1:
                break
            abs_off = code_start + idx
            disasm = r2.cmd(f"pd 5 @ {abs_off - 4}")
            print(f"  {name} at {hex(abs_off)}:")
            for line in disasm.strip().split('\n')[:5]:
                print(f"    {line}")
            count += 1
            idx += 1
    
    # If no AESNI found, the aes crate might use software implementation
    if not any(code_bytes.find(op) != -1 for op in aes_opcodes.keys()):
        print("  No AESNI instructions found - software AES implementation used.")
        # Look for the shift/xor patterns typical of software AES
        # The fixslice impl uses many XOR and shift operations
    
    # ─── 6. Analyze references to encrypted blob from code ────────────
    if hits_found:
        print("\n\n[6] ANALYZING FUNCTIONS THAT REFERENCE ENCRYPTED CONFIG")
        print("-" * 50)
        
        for hit_addr in hits_found:
            # Try to find the function containing this address
            # Go backwards until we find a function prologue (push rbp; mov rbp, rsp)
            prologue_search = r2.cmd(f"pd -200 @ {hit_addr}")
            
            # Save full disassembly around each reference
            context = r2.cmd(f"pd 200 @ {hit_addr - 256}")
            (OUTPUT / f"config_ref_{hit_addr:#x}.asm").write_text(context)
            
            print(f"\n  Function referencing config near {hex(hit_addr)}:")
            # Show just the interesting part
            for line in context.strip().split('\n'):
                if hex(hit_addr) in line or 'call' in line.lower() or 'ret' in line.lower():
                    print(f"    {line}")
    
    r2.quit()
    print(f"\n\nAll output saved to {OUTPUT}/")

if __name__ == "__main__":
    main()
