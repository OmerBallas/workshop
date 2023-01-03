import sys
import ipaddress
import socket

import userp as up


def send_rules(path):
    def parse_ip(ip_string):
        splited = ip_string.split("/")
        if (len(splited) != 2):
            print("error in ip1")
            exit(-1)
        try:
            ip = socket.htonl(int(ipaddress.IPv4Address(splited[0])))
            prefix = int(splited[1])
            return (ip,prefix)
        except:
            print("error in ip2")
            exit(-1)

    with open(path, 'r') as f:
        temp = f.read().splitlines()
        l = []
        count = 0
        up.fit6(1)
        for i in range(len(temp)):
            li = list(temp[count].split(" "))
            name = li[0]
            if (li[1] == "in"):
                direction = 1
            elif (li[1] == "out"):
                direction = 2
            elif (li[1] == "any"):
                direction = 1 | 2
            else:
                print("error in direction")
                exit(-1)
            if (li[2] == "any"):
                src_ip = 0
                src_prefix_size = 0
            else:
                # parse ip
                src_ip, src_prefix_size = parse_ip(li[2])
            if (li[3] == "any"):
                dst_ip = 0
                dst_prefix_size = 0
            else:
                # parse ip
                dst_ip, dst_prefix_size = parse_ip(li[3])
            if (li[4] == "TCP"):
                protocol = 6
            elif (li[4] == "UDP"):
                protocol = 17
            elif (li[4] == "ICMP"):
                protocol = 1
            elif (li[4] == "other"):
                protocol = 255
            elif (li[4] == "any"):
                protocol = 143
            else:
                print("error in protocol")
                exit(-1)
            if (li[5] == "any"):
                src_port = 0
            elif (li[5] == ">1023"):
                src_port = 1023
            else:
                try:
                    src_port = int(li[5])
                except:
                    print("error in src_port")
                    exit(-1)
            if (li[6] == "any"):
                dst_port = 0
            elif (li[6] == ">1023"):
                dst_port = 1023
            else:
                try:
                    dst_port = int(li[6])
                except:
                    print("error in dst_port")
                    exit(-1)
            if (li[7] == "yes"):
                ack = 2
            elif (li[7] == "no"):
                ack = 1
            elif (li[7] == "any"):
                ack = 1 | 2
            else:
                print("error in ack")
                exit(-1)
            if (li[8] == "accept"):
                action = 1
            elif (li[8] == "drop"):
                action = 0
            else:
                print("error in action")
                exit(-1)
            l = [name, direction, src_ip, src_prefix_size, dst_ip, dst_prefix_size,
                    src_port, dst_port, protocol, ack, action]
            up.fit2(name, direction, src_ip, src_prefix_size, dst_ip, dst_prefix_size,
                    src_port, dst_port, protocol, ack, action)
            count += 1
        up.fit3(1)

def print_rules():
    ret = up.fit(1)
    for i in range(len(ret)):
        li = ret[i]
        name = li[0]
        if (li[1] == 1):
            direction = "in"
        elif (li[1] == 2):
            direction = "out"
        elif (li[1] == (1 | 2)):
            direction = "any"
        else:
            print("error in direction")
            exit(-1)
        if (li[2] == 0) and (li[3] == 0):
            src_ip = "any"
        else:
            # unparse ip
            src_ip = str(ipaddress.IPv4Address(socket.ntohl(li[2]))) + "/" + str(li[3])
        if (li[4] == 0) and (li[5] == 0):
            dst_ip = "any"
        else:
            # unparse ip
            dst_ip = str(ipaddress.IPv4Address(socket.ntohl(li[4]))) + "/" + str(li[5])
        if ((li[6] % 256)  == 6):
            protocol = "TCP"
        elif ((li[6] % 256) == 17):
            protocol = "UDP"
        elif ((li[6] % 256) == 1):
            protocol = "ICMP"
        elif ((li[6] % 256) == 255):
            protocol = "other"
        elif ((li[6] % 256) == 143):
            protocol = "any"
        else:
            print("error in protocol")
            exit(-1)
        if (li[7] == 0):
            src_port = "any"
        elif (li[7] == 1023):
            src_port = ">1023"
        else:
            src_port = str(li[7])
        if (li[8] == 0):
            dst_port = "any"
        elif (li[8] == 1023):
            dst_port = ">1023"
        else:
            dst_port = str(li[8])
        if (li[9] == 2):
            ack = "yes"
        elif (li[9] == 1):
            ack = "no"
        elif (li[9] == (1 | 2)):
            ack = "any"
        else:
            print("error in ack")
            exit(-1)
        if (li[10] == 1):
            action = "accept"
        elif (li[10] == 0):
            action = "drop"
        else:
            print("error in action")
            exit(-1)
        rule = [name,direction,src_ip,dst_ip,protocol,src_port,dst_port,ack,action]
        print(rule)

def reset_log():
    up.fit5(1)
def print_log():
    ret = up.fit4(1)
    for i in range(len(ret)):
        li = ret[i]
        time_stamp = li[0]
        if ((li[1] % 256)  == 6):
            protocol = "TCP"
        elif ((li[1] % 256) == 17):
            protocol = "UDP"
        elif ((li[1] % 256) == 1):
            protocol = "ICMP"
        elif ((li[1] % 256) == 255):
            protocol = "other"
        elif ((li[1] % 256) == 143):
            protocol = "any"
        else:
            print("error in protocol")
            exit(-1)
        if (li[2] == 1):
            action = "accept"
        elif (li[2] == 0):
            action = "drop"
        else:
            print("error in action")
            exit(-1)
        if (li[3] == 0):
            src_ip = "any"
        else:
            # unparse ip
            src_ip = str(ipaddress.IPv4Address(socket.ntohl(li[3])))
        if (li[4]):
            src_port = "any"
        elif (li[4] == 1023):
            src_port = ">1023"
        else:
            src_port = str(li[4])
        if (li[5] == 0):
            dst_ip = "any"
        else:
            # unparse ip
            dst_ip = str(ipaddress.IPv4Address(socket.ntohl(li[5])))
        if (li[6] == 0):
            dst_port = "any"
        elif (li[6] == 1023):
            dst_port = ">1023"
        else:
            dst_port = str(li[12])
        if(li[7] == -1):
            reason = "fw inactive"
        elif(li[7] == -2):
            reason = "no match"
        elif(li[7] == -4):
            reason = "xms"
        elif(li[7] == -6):
            reason = "illegal value"
        else:
            reason = li[7]
        count = li[8]
        print([time_stamp, src_ip, dst_ip, src_port, dst_port, protocol, action, reason, count])

def print_conns():
    ret = up.fit7(1)
    state_dict = {-1:"State Error", 0:"Listening", 1:"SYN sent",2:"SYN recived",3:"Close wait",4:"Last ACK",5:"FIN wait 1",6:"FIN wait 2",
                  7:"Closed",8:"Established TCP connection",9:"Established FTP control connection",
                  10:"Established FTP data connection",11:"Established HTTP connection"}
    for i in range(len(ret)):
        li = ret[i]
        src_ip = str(ipaddress.IPv4Address(socket.ntohl(li[0])))
        src_port = li[1]
        dst_ip = str(ipaddress.IPv4Address(socket.ntohl(li[2])))
        dst_port = li[3]
        state = state_dict[li[4]]
        conn = [src_ip,src_port,dst_ip,dst_port,state]
        print(conn)

if __name__ == '__main__':
    if(sys.argv[1] == "show_rules"):
        print_rules()
    elif(sys.argv[1] == "load_rules"):
        send_rules(sys.argv[2])
    elif(sys.argv[1] == "show_log"):
        print_log()
    elif(sys.argv[1] == "clear_log"):
        reset_log()
    elif(sys.argv[1] == "show_conns"):
        print_conns()
    else:
        print("invalid input")




