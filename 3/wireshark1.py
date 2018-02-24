#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import dpkt
import socket
import argparse 
from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    # wow this is shitty, is there really not a better way to do it?
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def parse_packets(filename):
    number_of_packets = 0 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    input_data=dpkt.pcap.Reader(open(filename,'r'))


    for timestamp, packet in input_data:
        pass 

    output = list() # string buffer
    output.append("CS 352 Wireshark, part 1")
    output.append("Total number of packets, {}".format(number_of_packets))
    return '\n'.join(output)

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    args = vars(parser.parse_args())

    filename = args['filename']

    report = parse_packets(filename)

    print(report)

if __name__ == "__main__":
    main()
