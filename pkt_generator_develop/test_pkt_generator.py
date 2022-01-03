# Questo è il file di test che uso per controllare che la generazione de pkt funzioni correttamente

import unittest
from unittest import TestCase
from scapy.config import conf

from pkt_generator_develop.pkt_generator import get_ARP_resp_HWAddr, get_response_ICMP_ping


class Test(TestCase):
    def setUp(self) -> None:
        conf.verb = 0
        # pass

    def test_generate_arp_request(self):
        ans = get_ARP_resp_HWAddr("192.168.238.0/24")
        print(ans)
        self.assertIsNotNone(ans)

    def test_get_ping_response_from_monitor(self):
        result = get_response_ICMP_ping("192.168.238.4")
        self.assertEqual("192.168.238.4", result.src)

if __name__ == '__main__':
    unittest.main()
