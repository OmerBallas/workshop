import socket
import os
import ipaddress
import http_driver as hd
import threading

#checks if this is a valid http response.
def valid_http_resp(data):
    header = data.split(sep="{s1}{s2}".format(s1=os.linesep, s2=os.linesep))[0]
    content_type = [field for field in header.splitlines() if "Content-Type" in field]
    for entry in content_type:
        if ("text/csv" in entry) or ("application/zip" in entry):
            return False
    return True

def thread_func(client_socket, client_address):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            original_ip = ipaddress.IPv4Address(client_address[0])
            new_ip = ipaddress.IPv4Address(socket.ntohl(hd.fit2(socket.htonl(int(original_ip)), client_address[1])))
            server_socket.bind(("", 0))
            hd.fit(socket.htonl(int(original_ip)), client_address[1], socket.htonl(int(new_ip)), 80,
                   server_socket.getsockname()[1])
            server_socket.connect((str(new_ip), 80))
            while True:
                data = client_socket.recv(2 ** 14).decode()
                if not data:
                    break
                try:
                    while True:
                        data += client_socket.recv(2 ** 14, socket.MSG_DONTWAIT).decode()
                except:
                    pass
                server_socket.sendall(data.encode())
                data2 = server_socket.recv(2 ** 14).decode()
                if not data2:
                    break
                try:
                    while True:
                        data2 += server_socket.recv(2 ** 14, socket.MSG_DONTWAIT).decode()
                except:
                    pass
                if valid_http_resp(data2):
                    client_socket.sendall(data2.encode())
        finally:
            server_socket.close()
    finally:
        client_socket.close()


if __name__ == '__main__':
    client_socket_bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket_bind.bind(("", 800))
    client_socket_bind.listen()
    thread_list = []
    try:
        while True:
            (client_socket, client_address) = client_socket_bind.accept()
            thread = threading.Thread(target=thread_func, args=(client_socket, client_address))
            thread_list.append(thread)
            thread.start()
    finally:
        client_socket_bind.close()