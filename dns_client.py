import sys
import socket
import dns_parse
import binascii 

server = '8.8.8.8'
useTcp = False
host = 'google.com'
try:
    typeList = ['IANA', 'A', 'NS', 'CNAME', 'SOA', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'ANY']
    if sys.argv[1] != "-t":
        print("Sorry, please input a Type.")
        sys.exit()
    elif (sys.argv[2] not in typeList):
        print("Sorry, please enter a valid Type.")      #if the first argument is -t and if what follows is valid, else exit
        sys.exit()

    if sys.argv[3] == "--tcp":                           
        useTcp = True                                   #if the third arg is --tcp, set the useTcp variable
        server = sys.argv[4]                            #set the following (the fourth) variable to the DNS server IP address
        host = sys.argv[5]                              #set the fifth variable to the host name
    elif sys.argv[3] != "--tcp":                        
        server = sys.argv[3]                            #if --tcp is not a flag, set the third variable to DNS IP Address
        host = sys.argv[4]                              #set the last variable to the host name

except Exception:
        print('Sorry, please enter valid arguments.')    #in case any of these are out of bounds, should only occur if there are too few arguments
        sys.exit()


def composeMsg():
    hostCount = str(hex(len(host.split(".")[0]))).encode()
    #hostCount[0] = "\\"
    header = bytearray(b'\xbe\xef\x05\x20\x00\x01\x00\x00\x00\x00\x00\x00')
    for char in host.split('.'):
        header.append(len(char))
        char = char.strip('/n')
        header += str.encode(char)
        
    if sys.argv[2] == "A":
        QType = b'\x00\x01'
    elif sys.argv[2] == "NS":
        QType = b'\x00\x02'
    elif sys.argv[2] == "CNAME":
        QType = b'\x00\x05'
    elif sys.argv[2] == "SOA":
        QType = b'\x00\x06'
    elif sys.argv[2] == "WKS":
        QType = b'\x00\x0b'
    elif sys.argv[2] == "PTR":
        QType = b'\x00\x0c'
    elif sys.argv[2] == "HINFO":
        QType = b'\x00\x0d'
    elif sys.argv[2] == "MINFO":
        QType = b'\x00\x0e'
    elif sys.argv[2] == "MX":
        QType = b'\x00\x0f'
    elif sys.argv[2] == "TXT":
        QType = b'\x00\x10'
    elif sys.argv[2] == "ANY":
        QType = b'\x00\xff'
    elif sys.argv[2] == "IANA":
        QType = b'\x00\x1c'
    else:
        print("Sorry, please enter a valid Type.")
        sys.exit()

    header = header + b'\x00' + QType + b'\x00\x01'
    #header = b'\xbe\xef\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x05apple\x03com\x00\x00\xff\x00\x01'
    return header

class DNSClient:
    def __init__(self, server):
        if useTcp == False:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif useTcp == True:
            self.socket = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
            self.socket.settimeout(5)
        
        self.socket.settimeout(60)
        self.socket.connect((server, 53))

    def send_query(self):
        query = composeMsg()
        
        print("The Query we are sending is:")
        print(query)
        
        self.socket.send(query)
        resp = self.socket.recv(1024)
        
        print("\nThe response we received is:")
        print(resp)
        print("\n")
        
        dns_parse.run(resp)
        
    def disconnect(self):
        self.socket.close()


if __name__ == '__main__':
    client = DNSClient(server)
    client.send_query()
    client.disconnect()
