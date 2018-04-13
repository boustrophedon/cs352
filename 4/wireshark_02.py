#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse

class Probes(object):
    def __init__(self, w, n):
        self.w = w
        self.n = n
        self.probes = dict()

    def add(self, packet, timestamp):
        pass

class Scans(object):
    def __init__(self, w, n):
        self.w = w
        self.n = n
        self.scans = dict()

    def add(self, packet, timestamp):
        pass

# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.

def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'r'))

    probes = Probes()
    scans = Scans()

    for timestamp, packet in input_data:
        
        # your code goes here ...
        probes.add(packet, timestamp)
        scans.add(packet, timestamp)

# execute a main function in Python
if __name__ == "__main__":
    main()
