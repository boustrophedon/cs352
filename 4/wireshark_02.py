#!/usr/bin/env python

import datetime
import socket
import argparse

from collections import defaultdict, namedtuple

import dpkt

Packet = namedtuple("Packet", ["timestamp","dport","src"])

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
      datetime.datetime.utcfromtimestamp(packet.timestamp),
      packet.dport,
      packet.src)

def flatmap(lists):
    output = list()
    for l in lists:
        output.extend(l)
    return output

def scan_matcher(cluster_p, test_p, w):
    return abs(cluster_p.dport - test_p.dport) <= w

def probe_matcher(cluster_p, test_p, w):
    return ((cluster_p.dport == test_p.dport) and abs(cluster_p.timestamp - test_p.timestamp) <= w)

def match_clusters(clusters, packet, matcher, w):
    matches = list()
    for cluster in clusters:
        for cluster_p in cluster:
            if matcher(cluster_p, packet, w):
                matches.append(cluster)
                break
    return matches

def find_clusters(packets, matcher, w, n):
    clusters = list()
    for packet in packets:
        matches = match_clusters(clusters, packet, matcher, w)

        if not matches:
            clusters.append([packet,])
        else:
            for match in matches:
                clusters.remove(match)
            joined = flatmap(matches)
            joined.append(packet)
            clusters.append(joined)

    output = list()
    for cluster in clusters:
        if len(cluster) >= n:
            output.append(cluster)

    return output


def find_probes(tcp, udp, w, n):
    tcp_clusters = find_clusters(tcp, probe_matcher, w, n)
    udp_clusters = find_clusters(udp, probe_matcher, w, n)

    return tcp_clusters, udp_clusters

def find_scans(tcp, udp, w, n):
    tcp_clusters = find_clusters(tcp, scan_matcher, w, n)
    udp_clusters = find_clusters(udp, scan_matcher, w, n)

    return tcp_clusters, udp_clusters

def parse_pcap(file_name, target_ip, W_p, N_p, W_s, N_s):
    input_data = dpkt.pcap.Reader(open(file_name,'r'))

    tcp = list()
    udp = list()
    for timestamp, packet in input_data:
        eth = dpkt.ethernet.Ethernet(packet)
        if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            dst = inet_to_str(ip.dst)
            src = inet_to_str(ip.src)
            if dst != target_ip:
                continue

            if type(ip.data) == dpkt.tcp.TCP:
                tcp.append(Packet(timestamp, ip.data.dport, src))
            if type(ip.data) == dpkt.udp.UDP:
                udp.append(Packet(timestamp, ip.data.dport, src))

    tcp_probes, udp_probes = find_probes(tcp, udp, W_p, N_p)
    tcp_scans, udp_scans = find_scans(tcp, udp, W_s, N_s)

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

    print("CS 352 Wireshark (Part 2)")
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
