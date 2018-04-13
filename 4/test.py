import unittest
from wireshark_02 import parse_pcap

import re

scan_re = re.compile("Found (.*) scans")
probe_re = re.compile("Found (.*) probes")

def get_num_scans(report_text):
  tcp, udp = scan_re.findall(report_text)

  return int(tcp), int(udp)

def get_num_probes(report_text):
  tcp, udp = probe_re.findall(report_text)

  return int(tcp), int(udp)


class TestWireshark2(unittest.TestCase):
  def check_pcap(self, report_fname, pcap_fname, target_ip, W_p, N_p, W_s, N_s):
      scan_tcp, scan_udp = get_num_scans(open(report_fname).read())
      probe_tcp, probe_udp = get_num_probes(open(report_fname).read())
      
      tcp_probes, udp_probes, tcp_scans, udp_scans = parse_pcap(pcap_fname, target_ip, W_p, N_p, W_s, N_s)

      self.assertEqual(len(tcp_probes), probe_tcp)
      self.assertEqual(len(udp_probes), probe_udp)
      self.assertEqual(len(tcp_scans), scan_tcp)
      self.assertEqual(len(udp_scans), scan_udp)

  def test_probe1(self):
    report_f = "output-probe_001.txt"
    pcap_f = "probe_001.pcap"

    self.check_pcap(report_f, pcap_f, "192.168.2.240", 3, 4, 10, 4)

  def test_probe2(self):
    report_f = "output-probe_002.txt"
    pcap_f = "probe_002.pcap"

    self.check_pcap(report_f, pcap_f, "192.168.2.240", 3, 4, 10, 4)

  def test_scan1(self):
    report_f = "output-scan_001.txt"
    pcap_f = "scan_001.pcap"

    self.check_pcap(report_f, pcap_f, "192.168.2.240", 3, 4, 10, 4)
    scan_tcp, scan_udp = get_num_scans(open(report_f).read())

  def test_scan2(self):
    report_f = "output-scan_002.txt"
    pcap_f = "scan_002.pcap"

    self.check_pcap(report_f, pcap_f, "192.168.2.240", 3, 4, 10, 4)
  
if __name__ == '__main__':
  unittest.main()
