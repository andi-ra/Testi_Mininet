import argparse
import ipaddress
import random
import shlex
import subprocess

import scapy
from scapy import plist
from scapy.config import conf
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, UDP, TCP
from scapy.layers.l2 import Ether, ARP, arping
from scapy.packet import Raw
from scapy.sendrecv import srp, sr1, sniff, srloop, send, sendp, sendpfast
import iperf3
from time import sleep

from scapy.utils import PcapWriter

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


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


def stop_filter(x):
    if x.load == "Poison":
        return True
    else:
        return False


MAX_PACKET = 100

if __name__ == '__main__':
    # conf.verb = 0
    conf.iface = "eth0"
    my_parser = argparse.ArgumentParser(description='Packet generator based on scapy')
    group_addr = my_parser.add_mutually_exclusive_group()
    group_addr.add_argument('-n', '--netaddr', default=False, type=ipaddress.IPv4Network,
                            help='address to be "arpinged"')
    group_addr.add_argument('-a', '--address', default=False, type=ipaddress.IPv4Address,
                            help='address to be "pinged classically"')
    group = my_parser.add_mutually_exclusive_group()
    group.add_argument('--arping', action="store_true", default=False, help='ARP ping', )
    group.add_argument('--icmping', action="store_true", default=False, help='ICMP ping', )
    my_parser.add_argument("-m", "--monitor", action="store_true", default=False, help='Start arp monitor')
    my_parser.add_argument("-c", "--client", type=ipaddress.IPv4Address, default=False, help='Start iperf3 client')
    my_parser.add_argument("-s", "--server", action="store_true", default=False, help='Start iperf3 server')
    my_parser.add_argument("-c2", "--convertEth", action="store_true", default=False, help='Convert raw bytes to a pkt')
    my_parser.add_argument("-M", "--maxpacket", type=int, default=False, help='max packet to send')

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

    if args.maxpacket:
        MAX_PACKET = args.maxpacket

    if args.client:
        pkt_list = []
        packet = Ether(dst="08:00:00:00:00:01") / \
                 IP(dst=str(args.client)) / TCP(sport=random.randint(2000, 65535), dport=5202) / Raw("CIAO")
        pill = IP(dst=str(args.client)) / TCP(sport=random.randint(2000, 65535), dport=5201, flags="F") / Raw(" Poison")
        i = 0
        while i < MAX_PACKET:
            packet[TCP].sport = random.randint(1024, 65535)
            i = i + 1  # Da rifare meglio...
            pkt_list.append(packet)
        i = 0
        print("Sending fast")
        print(sendpfast(pkt_list, loop=1e5, parse_results=1, iface="eth0", replay_args=["topspeed"]))
        while i < 10:  # 10 pacchetti garantiscono che i monitor finiscono
            pill[TCP].sport = random.randint(1024, 65535)
            i = i + 1  # Da rifare meglio...
            send(pill)
        sleep(1)  # Messo per i test...

    if args.server:
        print("starting server monitor")
        result = sniff(iface="eth0",
                       stop_filter=lambda x: x[TCP].flags == "F" if x.haslayer(TCP) else None,
                       # prn=lambda x: x.summary() if x[TCP].flags == "S" else None)
                       prn=lambda x: x.summary())
        print("\n\nFinishing and cleaning up...")
