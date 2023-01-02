#https://realpython.com/python-sockets/
import socket
import os
import ipaddress
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(("127.0.0.1", 9999))
    server.listen()
    (client_socket, client_address) = server.accept()
    with client_socket:
        while True:
            data = client_socket.accept(1024)
            if not data:
                break
