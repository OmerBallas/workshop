import socket
count = 0;
ret = 0;
size = 5
while ((32 >= size) and (size > 0)):
    if (size >= 8):
        ret += ((1 << 8) - 1) << 8 * count
    else:
        ret += ((1 << 8) - (1 << (8 - size))) << count * 8;
    size -= 8
size = 27
a=((1<<32)-1)
b = ((1<<(32-size)) -1)
print(a)
print(b)
ret2 = a ^ b
print(ret2)
print(socket.htonl(ret2))

#4294967264