import argparse
import ipaddress

import scapy
from scapy.config import conf
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether, ARP, arping
from scapy.sendrecv import srp, sr1, sniff


def get_ARP_resp_HWAddr(address):
    ans, unans = arping(address)
    if ans is not None:
        return [pkt for pkt in ans[0]]
    else:
        return None


def convert_raw_bytes_to_eth_pkt(raw_bytes):
    packet = scapy.layers.l2.Ether(raw_bytes)
    return packet


def get_response_ICMP_ping(address):
    p = sr1(IP(dst=address) / ICMP(), timeout=3)
    if p is not None:
        return p
    else:
        return None


def arp_monitor_callback(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% % ARP.psrc%")


def monitor():
    sniff(prn=arp_monitor_callback, filter="arp", store=0)


if __name__ == '__main__':
    # conf.verb = 0
    my_parser = argparse.ArgumentParser(description='Packet generator based on scapy')
    group_addr = my_parser.add_mutually_exclusive_group()
    group_addr.add_argument('-n', '--netaddr', type=ipaddress.IPv4Network, help='address to be "arpinged"')
    group_addr.add_argument('-a', '--address', type=ipaddress.IPv4Address, help='address to be "pinged classically"')
    group = my_parser.add_mutually_exclusive_group()
    group.add_argument('--arping', action="store_true", default=False, help='ARP ping', )
    group.add_argument('--icmping', action="store_true", default=False, help='ICMP ping', )
    my_parser.add_argument("-m", "--monitor", action="store_true", default=False, help='Start arp monitor')
    my_parser.add_argument("-c2", "--convertEth", action="store_true", default=False, help='Convert raw bytes to a pkt')

    args = my_parser.parse_args()

    print("Starting packet generator...\n")
    if args.arping:
        print("Sending out ARP messages")
        print(str(args.netaddr))
        ans = get_ARP_resp_HWAddr(str(args.netaddr))
        for pkt in ans:
            pkt.show()
            print(30 * "*")
            print()
    if args.icmping:
        print("pinging " + str(args.address))
        pkt = get_response_ICMP_ping(args.address)
        pkt.show()
    if args.monitor:
        monitor()
    if args.convertEth:
        pkt = convert_raw_bytes_to_eth_pkt
