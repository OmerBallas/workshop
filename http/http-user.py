import socket
import os
import ipaddress
import http_driver as hd
client_socket_bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_bind.bind(("",800))
client_socket_bind.listen()
print("server up")
(client_socket, client_address) = client_socket_bind.accept()
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
original_ip = ipaddress.IPv4Address(client_address[0])
print("accepted comms from: {p}".format(p=client_address))
print("ip: {ip}, port: {port}".format(ip = socket.htonl(int(original_ip)), port =client_address[1]))
new_ip = ipaddress.IPv4Address(socket.htonl(hd.fit2(socket.htonl(int(original_ip)),client_address[1])))
print("new_ip: {ip}".format(ip=str(new_ip)))
server_socket.bind(("",0))
hd.fit(socket.htonl(int(original_ip)), client_address[1], socket.htonl(int(new_ip)), 80,server_socket.getsockname()[1])
server_socket.connect((str(new_ip),80))
print("connected to: {p}".format(p=server_socket.getpeername()))
data = client_socket.recv(8190,socket.MSG_DONTWAIT).decode()
print("data:")
print(data)
try:
    while True:
        data += client_socket.recv(8190, socket.MSG_DONTWAIT).decode()
except:
    pass

data = data.split(sep="{s1}{s2}".format(s1=os.linesep,s2=os.linesep))[0]
#print(data)
server_socket.sendall(data.encode())
data2 = server_socket.recv(8190).decode()
try:
    while True:
        data2 += server_socket.recv(8190, socket.MSG_DONTWAIT).decode()
except:
    pass

client_socket.send(data2.encode())
client_socket.close()
server_socket.close()
client_socket_bind.close()