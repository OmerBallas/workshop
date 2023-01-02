import socket
import os
import ipaddress

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1",9999))
client.sendall("hi".encode())
client.close()