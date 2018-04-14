#!/usr/bin/env python

import datetime
import socket
import argparse

from collections import defaultdict

from abc import ABCMeta, abstractmethod

import dpkt

class PacketCluster(object):
    __metaclass__ = ABCMeta
    def __init__(self, tcp_packets, udp_packets):
        self.tcp_packets = list(tcp_packets)
        self.udp_packets = list(udp_packets)

        self.tcp_packets.sort(key=self.feature)
        self.udp_packets.sort(key=self.feature)

    @abstractmethod
    def feature(self, packet):
        pass

    @abstractmethod
    def in_cluster(self, cluster, packet):
      pass

    @abstractmethod
    def merge_clusters(self, clusters):
      pass

    def find_clusters(self, dst_addr, w, n):
        tcp_clusters = self._find_clusters(self.tcp_packets, dst_addr, w, n)
        udp_clusters = self._find_clusters(self.udp_packets, dst_addr, w, n)

        tcp_clusters = self.merge_clusters(tcp_clusters)
        udp_clusters = self.merge_clusters(udp_clusters)

        return (tcp_clusters, udp_clusters)

    def _find_clusters(self, packets, dst_addr, w, n):
        clusters = list()
        if len(packets) == 0:
            return clusters
            
        curr = list()
        for packet in packets:
            if not curr:
                curr.append(packet)
                continue
            if packet[3] != dst_addr:
              continue


            if self.in_cluster(curr, packet, w):
                curr.append(packet)

            else:
                if len(curr) >= n:
                    clusters.append(list(curr))
                curr = [packet]

        # we might have ended on a cluster
        #if len(curr) >= n:
        #    clusters.append(list(curr))
        #    curr = list()
        return clusters

class Probes(PacketCluster):
    def __init__(self, tcp_packets, udp_packets):
        super(Probes, self).__init__(tcp_packets, udp_packets)

    def feature(self, packet):
        # timestamp
        return packet[0]

    def merge_clusters(self, clusters):
      to_merge = defaultdict(list)

      for cluster in clusters:
        to_merge[cluster[0][1].dport].append(cluster)

      merged = list()
      for _,group in to_merge.items():
        merged_group = list()
        for cluster in group:
          merged_group.extend(cluster)
        merged_group.sort(key=self.feature)

        merged.append(merged_group)

      return merged

    def in_cluster(self, cluster, packet, w):
      return ((cluster[0][2] == packet[2]) 
          and (cluster[0][1].dport == packet[1].dport) 
          and abs(self.feature(packet) - self.feature(cluster[-1])) <= w)

class Scans(PacketCluster):
    def __init__(self, tcp_packets, udp_packets):
        super(Scans, self).__init__(tcp_packets, udp_packets)

    def feature(self, packet):
        # port
        return packet[1].dport

    def merge_clusters(self, clusters):
      to_merge = defaultdict(list)

      for cluster in clusters:
        to_merge[cluster[0][1].dport].append(cluster)

      merged = list()
      for _,group in to_merge.items():
        merged_group = list()
        for cluster in group:
          merged_group.extend(cluster)
        merged_group.sort(key=self.feature)

        merged.append(merged_group)

      return merged

    def in_cluster(self, cluster, packet, w):
      return ((cluster[0][2] == packet[2]) 
        and abs(self.feature(packet) - self.feature(cluster[-1])) <= w)


# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.

def format_packet(packet):
  return "        Packet: [Timestamp: {}, Port: {}, Source IP: {}]".format(
      datetime.datetime.utcfromtimestamp(packet[0]),
      packet[1].dport,
      packet[2],
  )

def parse_pcap(file_name, target_ip, W_p, N_p, W_s, N_s):
    input_data = dpkt.pcap.Reader(open(file_name,'r'))

    tcp = list()
    udp = list()
    for timestamp, packet in input_data:
        eth = dpkt.ethernet.Ethernet(packet)
        if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            src = inet_to_str(ip.src)
            dst = inet_to_str(ip.dst)
            if type(ip.data) == dpkt.tcp.TCP:
                tcp.append((timestamp, ip.data, src, dst))
            if type(ip.data) == dpkt.udp.UDP:
                udp.append((timestamp, ip.data, src, dst))

    probes = Probes(tcp, udp)
    scans = Scans(tcp, udp)

    tcp_probes, udp_probes = probes.find_clusters(target_ip, W_p, N_p)
    tcp_scans, udp_scans = scans.find_clusters(target_ip, W_s, N_s)

    return (tcp_probes, udp_probes, tcp_scans, udp_scans)

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


    tcp_probes, udp_probes, tcp_scans, udp_scans = parse_pcap(file_name, target_ip, W_p, N_p, W_s, N_s)

    print("Found {} probes".format(len(tcp_probes)))
    print("Found {} scans".format(len(tcp_scans)))
    print("Found {} probes".format(len(udp_probes)))
    print("Found {} scans".format(len(udp_scans)))


    print("Reports for TCP")
    print("Found {} probes".format(len(tcp_probes)))
    for cluster in tcp_probes:
      print("Probe: [{} packets]".format(len(cluster)))
      for packet in cluster:
        print(format_packet(packet))

    print("Found {} scans".format(len(tcp_scans)))
    for cluster in tcp_scans:
      print("Probe: [{} packets]".format(len(cluster)))
      for packet in cluster:
        print(format_packet(packet))

    print("Reports for UDP")
    print("Found {} probes".format(len(udp_probes)))
    for cluster in udp_probes:
      print("Probe: [{} packets]".format(len(cluster)))
      for packet in cluster:
        print(format_packet(packet))

    print("Found {} scans".format(len(udp_scans)))
    for cluster in udp_scans:
      print("Probe: [{} packets]".format(len(cluster)))
      for packet in cluster:
        print(format_packet(packet))


# execute a main function in Python
if __name__ == "__main__":
    main()
