#!/usr/bin/env python2

# This is the skeleton code of a cs 352 socket
# You must change the code in the pass statements to make the client and server work. 

import socket as ip

class socket:
    
    def __init__(self):
        self.sock = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)

    def socket():
        pass
    
    def bind(self,address):
        self.sock.bind(address)

    def sendto(self,buffer,address):
        self.sock.sendto(buffer, address)

    def recvfrom(self,nbytes):
        return self.sock.recvfrom(nbytes)

    def close(self):
        self.sock.close()

