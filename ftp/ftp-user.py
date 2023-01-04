import socket
import os
import ipaddress
import ftp_driver as fd
import threading


def thread_func(client_socket, client_address):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            original_ip = ipaddress.IPv4Address(client_address[0])
            new_ip = ipaddress.IPv4Address(socket.ntohl(fd.fit2(socket.htonl(int(original_ip)), client_address[1])))
            server_socket.bind(("", 0))
            fd.fit(socket.htonl(int(original_ip)), client_address[1], socket.htonl(int(new_ip)), 21,
                   server_socket.getsockname()[1])
            server_socket.connect((str(new_ip), 21))
            while True:
                data2 = server_socket.recv(2 ** 14).decode()
                if not data2:
                    break
                try:
                    while True:
                        data2 += server_socket.recv(2 ** 14, socket.MSG_DONTWAIT).decode()
                except:
                    pass
                if True:
                    client_socket.sendall(data2.encode())
                data = client_socket.recv(2 ** 14).decode()
                if not data:
                    break
                try:
                    while True:
                        data += client_socket.recv(2 ** 14, socket.MSG_DONTWAIT).decode()
                except:
                    pass
                if "PORT" in data:
                    new_port = int(data.split(sep=",")[-1]) + 256 * int(data.split(sep=",")[-2])
                    fd.fit3(socket.htonl(int(original_ip)), socket.htonl(int(new_ip)), new_port)
                server_socket.sendall(data.encode())
        finally:
            server_socket.shutdown(socket.SHUT_RDWR)
            server_socket.close()
    finally:
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()


if __name__ == '__main__':
    client_socket_bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket_bind.bind(("", 210))
    client_socket_bind.listen()
    thread_list = []
    try:
        while True:
            (client_socket, client_address) = client_socket_bind.accept()
            thread = threading.Thread(target=thread_func, args=(client_socket, client_address))
            thread_list.append(thread)
            thread.start()
    finally:
        client_socket_bind.shutdown(socket.SHUT_RDWR)
        client_socket_bind.close()