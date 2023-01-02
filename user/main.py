import sys


import userp as up


def ip_str_pref(b1, b2, b3, b4, prefix):
    return "{b1}.{b2}.{b3}.{b4}/{prefix}".format(b1=b1, b2=b2, b3=b3, b4=b4, prefix=prefix)
def ip_str(b1, b2, b3, b4):
    return "{b1}.{b2}.{b3}.{b4}".format(b1=b1, b2=b2, b3=b3, b4=b4)

def send_rules(path):
    def parse_ip(ip_string):
        l = ip_string.split(".")
        if (len(l) != 4):
            print("error in ip")
            exit(-1)
        l2 = l[3].split("/")
        if (len(l2) != 2):
            print("error in ip")
            exit(-1)
        try:
            b1 = int(l[0])
            b2 = int(l[1])
            b3 = int(l[2])
            b4 = int(l2[0])
            prefix = int(l2[1])
            return (b1,b2,b3,b4,prefix)
        except:
            print("error in ip")
            exit(-1)

    with open(path, 'r') as f:
        temp = f.read().splitlines()
        l = []
        count = 0
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
                src_ip1 = 0
                src_ip2 = 0
                src_ip3 = 0
                src_ip4 = 0
                src_prefix_size = 0
            else:
                # parse ip
                src_ip1,src_ip2,src_ip3,src_ip4, src_prefix_size = parse_ip(li[2])
            if (li[3] == "any"):
                dst_ip1 = 0
                dst_ip2 = 0
                dst_ip3 = 0
                dst_ip4 = 0
                dst_prefix_size = 0
            else:
                # parse ip
                dst_ip1,dst_ip2,dst_ip3,dst_ip4, dst_prefix_size = parse_ip(li[3])
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
            l = [name, direction, src_ip1, src_ip2,src_ip3,src_ip4, src_prefix_size, dst_ip1, dst_ip2,dst_ip3,dst_ip4, dst_prefix_size,
                    src_port, dst_port, protocol, ack, action]
            print(l)
            up.fit2(name, direction, src_ip1, src_ip2,src_ip3,src_ip4, src_prefix_size, dst_ip1, dst_ip2,dst_ip3,dst_ip4, dst_prefix_size,
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
        if ((li[2] == 0) and (li[3] == 0) and (li[4] == 0) and (li[5] == 0) and (li[6] == 0)):
            src_ip = "any"
        else:
            # unparse ip
            src_ip = ip_str_pref(li[2],li[3],li[4],li[5],li[6])
        if ((li[7] == 0) and (li[8] == 0) and (li[9] == 0) and (li[10] == 0) and (li[11] == 0)):
            dst_ip = "any"
        else:
            # unparse ip
            dst_ip = ip_str_pref(li[7],li[8],li[9],li[10],li[11])
        if ((li[12] % 256)  == 6):
            protocol = "TCP"
        elif ((li[12] % 256) == 17):
            protocol = "UDP"
        elif ((li[12] % 256) == 1):
            protocol = "ICMP"
        elif ((li[12] % 256) == 255):
            protocol = "other"
        elif ((li[12] % 256) == 143):
            protocol = "any"
        else:
            print("error in protocol")
            exit(-1)
        if (li[13] == 0):
            src_port = "any"
        elif (li[13] == 1023):
            src_port = ">1023"
        else:
            src_port = str(li[13])
        if (li[14] == 0):
            dst_port = "any"
        elif (li[14] == 1023):
            dst_port = ">1023"
        else:
            dst_port = str(li[14])
        if (li[15] == 2):
            ack = "yes"
        elif (li[15] == 1):
            ack = "no"
        elif (li[15] == (1 | 2)):
            ack = "any"
        else:
            print("error in ack")
            exit(-1)
        if (li[16] == 1):
            action = "accept"
        elif (li[16] == 0):
            action = "drop"
        else:
            print("error in action")
            exit(-1)
        rule = [name,direction,src_ip,dst_ip,protocol,src_port,dst_port,ack,action]
        print(rule)

def reset_rules():
    up.fit5()
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
        if ((li[3] == 0) and (li[4] == 0) and (li[5] == 0) and (li[6] == 0)):
            src_ip = "any"
        else:
            # unparse ip
            src_ip = ip_str(li[3],li[4],li[5],li[6])
        if (li[7] == 0):
            src_port = "any"
        elif (li[7] == 1023):
            src_port = ">1023"
        else:
            src_port = str(li[7])
        if ((li[8] == 0) and (li[9] == 0) and (li[10] == 0) and (li[11] == 0)):
            dst_ip = "any"
        else:
            # unparse ip
            dst_ip = ip_str(li[8],li[9],li[10],li[11])
        if (li[12] == 0):
            dst_port = "any"
        elif (li[12] == 1023):
            dst_port = ">1023"
        else:
            dst_port = str(li[12])
        if(li[13] == -1):
            reason = "fw inactive"
        elif(li[13] == -2):
            reason = "no match"
        elif(li[13] == -4):
            reason = "xms"
        elif(li[13] == -6):
            reason = "illegal value"
        else:
            reason = li[13]
        count = li[14]
        print([time_stamp, src_ip, dst_ip, src_port, dst_port, protocol, action, reason, count])

print("logs")
print_log()
print("reset")
reset_rules()
print("logs")
print_log()

"""
if __name__ == '__main__':
    if (sys.argv[1] ==  "show_rules") and (len(sys.argv) == 2):
        print_rules()
    elif (sys.argv[1] ==  "show_log") and (len(sys.argv) == 2):
        print_log()
"""





