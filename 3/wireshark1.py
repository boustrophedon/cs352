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
from collections import defaultdict

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
    ips = defaultdict(lambda: 0)
    dst_ports = defaultdict(lambda: 0)
    src_dst_pairs = defaultdict(lambda: 0)

    input_data=dpkt.pcap.Reader(open(filename,'r'))


    for timestamp, packet in input_data:
        number_of_packets+=1

        eth = dpkt.ethernet.Ethernet(packet)
        if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            src_addr = inet_to_str(ip.src)
            ips[src_addr] += 1
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                dst_port = tcp.dport
                dst_ports[dst_port] += 1
                src_dst_pairs[src_addr + ":" + str(dst_port)] += 1

    output = list() # string buffer
    output.append("CS 352 Wireshark, part 1")
    output.append("Total number of packets,{}".format(number_of_packets))
    output.append("Source IP addresses, count")
    for k,v in reversed(sorted(ips.iteritems(), key=lambda x: x[1])):
        output.append("{},{}".format(k,v))

    output.append("Destination TCP ports, count")
    for k,v in reversed(sorted(dst_ports.iteritems(), key=lambda x: x[1])):
        output.append("{},{}".format(k,v))

    output.append("Source IPs/Destination TCP ports, count")
    for k,v in reversed(sorted(src_dst_pairs.iteritems(), key=lambda x: x[1])):
        output.append("{},{}".format(k,v))

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
