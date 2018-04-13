#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse

from abc import ABCMeta, abstractmethod

class PacketCluster(object):
    __metaclass__ = ABCMeta
    def __init__(self, tcp_packets, udp_packets):
        self.tcp_packets = list(tcp_packets)
        self.udp_packets = list(udp_packets)

        self.tcp_packets.sort(key=lambda x: self.feature(x))
        self.udp_packets.sort(key=lambda x: self.feature(x))

    @abstractmethod
    def feature(self, packet):
        pass

    def find_clusters(self, w, n):
        tcp_clusters = self._find_clusters(self.tcp_packets, w, n)
        udp_clusters = self._find_clusters(self.udp_packets, w, n)

        return (tcp_clusters, udp_clusters)

    def _find_clusters(self, packets, w, n):
        clusters = list()
        if len(packets) == 0:
            return clusters
            
        curr = list()
        for packet in packets:
            if not curr:
                curr.append(packet)
                continue
            
            if (self.feature(packet) - self.feature(curr[-1])) <= w:
                curr.append(packet)
            else:
                if len(curr) >= n:
                    clusters.append(list(curr))
                    del curr[:]

        # we might have ended on a cluster
        if len(curr) >= n:
            clusters.append(list(curr))
            del curr[:]
        return clusters

class Probes(PacketCluster):
    def __init__(self, tcp_packets, udp_packets):
        super(Probes, self).__init__(tcp_packets, udp_packets)

    def feature(self, packet):
        # port
        return packet[1].dport

class Scans(PacketCluster):
    def __init__(self, tcp_packets, udp_packets):
        super(Scans, self).__init__(tcp_packets, udp_packets)

    def feature(self, packet):
        # timestamp
        return packet[0]



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

    tcp = list()
    udp = list()
    for timestamp, packet in input_data:
        eth = dpkt.ethernet.Ethernet(packet)
        if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            if type(ip.data) == dpkt.tcp.TCP:
                tcp.append((timestamp, ip.data))
            if type(ip.data) == dpkt.udp.UDP:
                udp.append((timestamp, ip.data))

    probes = Probes(tcp, udp)
    scans = Scans(tcp, udp)

    tcp_probes, udp_probes = probes.find_clusters(W_p, N_p)
    tcp_scans, udp_scans = scans.find_clusters(W_s, N_s)

    print("Report for TCP")
    print("Probes: {}".format(len(tcp_probes)))
    print("Scans: {}".format(len(tcp_scans)))

    print("Report for UDP")
    print("Probes: {}".format(len(udp_probes)))
    print("Scans: {}".format(len(udp_scans)))

# execute a main function in Python
if __name__ == "__main__":
    main()
