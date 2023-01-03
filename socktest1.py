#https://realpython.com/python-sockets/
import socket
import os
import ipaddress
import threading



def thread_fun(client_socket,client_address):
    try:
        while True:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            data = data.split(sep="{s1}{s2}".format(s1=os.linesep, s2=os.linesep))[0]
            print(data)
            data2 = [x for x in data.splitlines() if "Connection" in x]
            for entry in data2:
                print("keep-alive" in entry)
                print("blah" in entry)
            print(data2)
    finally:
        client_socket.close()





with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(("127.0.0.1", 9999))
    server.listen()
    l = []
    try:
        while True:
            (client_socket, client_address) = server.accept()
            t = threading.Thread(target=thread_fun,args=(client_socket,client_address))
            t.start()
            l.append(t)

    except KeyboardInterrupt:
        for t in l:
            t.join()

