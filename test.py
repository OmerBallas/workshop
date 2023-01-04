import socket
client_socket_bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_bind.bind(("", 21))
client_socket_bind.listen()
(client_socket, client_address) = client_socket_bind.accept()
print("accepted")
data = client_socket.recv(2 ** 14).decode()
print("data:")
print(data)
client_socket.close()
client_socket_bind.close()

#4294967264