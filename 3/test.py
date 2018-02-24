import unittest
import wireshark1

from itertools import izip_longest

class TestWireshark1(unittest.TestCase):
    def compare_to_file(self, pcap, expected_file):
        actual_report = wireshark1.parse_packets(pcap).split('\n')
        self.assertTrue(len(actual_report) > 0)

        with open(expected_file) as f:
            expected_report = [line.strip() for line in f]

            for actual in actual_report:
                # because the sort order is arbitrary for lines with equal
                # counts we have to do this shitty test and then test that the
                # number of lines are the same
                self.assertIn(actual, expected_report)
            self.assertEqual(len(actual_report), len(expected_report))

    def test_small(self):
        self.compare_to_file("small.pcap", "output-small.txt") 
    def test_medium(self):
        self.compare_to_file("medium.pcap", "output-medium.txt") 
    def test_http(self):
        self.compare_to_file("http.pcap", "output-http.txt") 

if __name__ == '__main__':
    unittest.main()
