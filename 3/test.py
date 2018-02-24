import unittest
import wireshark1


class TestWireshark1(unittest.TestCase):
    def compare_to_file(self, pcap, expected_file):
        actual_report = wireshark1.parse_packets(pcap)
        self.assertTrue(len(actual_report) > 0)

        with open(expected_file) as f:
            expected_report = [line.strip() for line in f]
            for expected, actual in zip(expected_report, actual_report.split('\n')):
                self.assertEqual(expected, actual)

    def test_small(self):
        self.compare_to_file("small.pcap", "output-small.txt") 
    def test_medium(self):
        self.compare_to_file("medium.pcap", "output-medium.txt") 
    def test_http(self):
        self.compare_to_file("http.pcap", "output-http.txt") 

if __name__ == '__main__':
    unittest.main()
