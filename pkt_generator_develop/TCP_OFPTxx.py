"""Questo è il file che mi serve per testare in TCP la riuscita della connessione """
import dataclasses
import socket
from time import sleep

from pyof.foundation.basic_types import UBInt32, UBInt16, UBInt8, UBInt64, DPID
from pyof.utils import unpack, validate_packet
from pyof.v0x01.asynchronous.packet_in import PacketIn
from pyof.v0x01.common.action import ActionType
from pyof.v0x01.common.header import Header
from pyof.v0x01.controller2switch.features_reply import FeaturesReply
from pyof.v0x01.controller2switch.features_reply import Capabilities
from pyof.v0x01.asynchronous.packet_in import PacketInReason
from pyof.v0x01.controller2switch.flow_mod import FlowMod
from pyof.v0x01.symmetric.hello import Hello
from scapy.config import conf
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw, Padding
from scapy.sendrecv import sr1
from scapy.utils import rdpcap

@dataclasses.dataclass
class TLV:
    """
    Formato generico di rappresentazione dei parametri di rete, tutti sono in questo modo
    """
    type: int
    length: int
    value: bytes
    subtype: int = None


class LLDP(object):
    """
    Questa classe rappresenta il pacchetto LLDP come da `RFC 4957 <https://datatracker.ietf.org/doc/html/rfc4957>`_. Una
    delle "references" lì punta allo standard `IEEE-802.1ab <https://standards.ieee.org/standard/802_1AB-2016.html>`_.
    Troviamo in quello standard la descrizione del LLDPDU per la segnalazione dei dispositivi sulla rete.

    =========  ========  ========
    Chassis    Port      TTL
    =========  ========  ========
    Type       Type      Type
    Subtype    Subtype   Subtype
    Length     Length    Length
    Value      Value     Value
    =========  ========  ========

    """

    def __init__(self, raw_str):
        self._raw = bytes(raw_str)

    @property
    def chassis(self):
        return TLV(
            type=int(bytes.hex(self._raw[0:1]), 16) >> 1,
            length=int(bytes.hex(self._raw[1:2]), 16),
            subtype=int(bytes.hex(self._raw[2:3]), 16),
            value=self._raw[3:24],
        )

    @property
    def port(self):
        return TLV(
            type=int(bytes.hex(self._raw[24:25]), 16) >> 1,
            length=int(bytes.hex(self._raw[25:26]), 16),
            subtype=int(bytes.hex(self._raw[26:27]), 16),
            value=self._raw[27:31]
        )

    @property
    def TTL(self):
        return TLV(
            type=bytes.hex(self._raw[31:32]),
            length=bytes.hex(self._raw[32:33]),
            value=bytes.hex(self._raw[33:35]),
        )


TIMEOUT = 2
conf.verb = 0
if __name__ == '__main__':
    ip = "192.168.238.9"
    sleep(1)
    print("Starting TCP sender OpenFlow packet forging...")
    packet = IP(dst=str(ip), ttl=20) / ICMP()
    reply = sr1(packet, timeout=TIMEOUT)
    if not (reply is None):
        print(ip, "is online")
    else:
        print("Timeout waiting for %s" % packet[IP].dst)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pkt_list = rdpcap("openflow.pcapng")
    # Connect the socket to the port where the server is listening
    server_address = (str(ip), 6653)
    print('connecting to %s port %s' % server_address)
    sock.connect(server_address)
    sock.settimeout(2)
    fake_pkt = Ether(pkt_list[11])
    print(fake_pkt.payload)
    try:
        print('sending ')
        arppkt = Ether() / ARP()
        arppkt[ARP].hwsrc = "00:11:22:aa:bb:cc"
        arppkt[ARP].pdst = "172.16.20.1"
        arppkt[Ether].dst = "ff:ff:ff:ff:ff:ff"
        packet = Hello()
        sock.sendall(packet.pack())
        data = sock.recv(4096)
        # print(bytes(data))
        msg = unpack(data)
        print(msg.header.message_type)

        packet = PacketIn(buffer_id=UBInt32(1), total_len=UBInt16(len(arppkt)) + len(Ether() / IP() / TCP()),
                          reason=PacketInReason.OFPR_NO_MATCH, data=bytes(arppkt), in_port=UBInt16(1))
        sock.sendall(packet.pack())
        data = sock.recv(4096)
        feature_request = unpack(data)
        # print(feature_request)
        packet = FeaturesReply(xid=Header(feature_request).xid, datapath_id=DPID(str('00:00:00:00:00:00:02:01')),
                               n_buffers=UBInt32(1), n_tables=UBInt8(0), capabilities=Capabilities.OFPC_ARP_MATCH_IP,
                               actions=ActionType.OFPAT_VENDOR, ports=None)
        sock.sendall(packet.pack())
        packet = PacketIn(buffer_id=UBInt32(1), total_len=UBInt16(len(arppkt)) + len(Ether() / IP() / TCP()),
                          reason=PacketInReason.OFPR_NO_MATCH, data=bytes(arppkt), in_port=UBInt16(1))
        sock.sendall(packet.pack())
        data = sock.recv(4096)
        packet_out = FlowMod(unpack(data))
        # print(packet_out.actions)
        chassis = bytearray(7)
        chassis[0:3] = (0x02, 0x06, 0x07)
        chassis[3:] = str.encode('fakey', 'utf-8')
        sysname = bytearray(7)
        sysname[0:2] = (0x0a, 0x05)
        sysname[2:] = str.encode('Lies!', 'utf-8')
        sysdesc = bytearray(12)
        sysdesc[0:2] = (0x0c, 0x0a)
        sysdesc[2:] = str.encode('MS-DOS 1.0', 'utf-8')
        portID = bytearray((0x04, 0x07, 0x03, 0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd))  # fake MAC address
        TTL = bytearray((0x06, 0x02, 0x00, 0x78))
        end = bytearray((0x00, 0x00))
        payload = bytes(chassis + portID + TTL + sysname + sysdesc + end)
        mac_lldp_multicast = '01:80:c2:00:00:0e'
        eth = Ether(src='00:01:02:ff:fe:fd', dst=mac_lldp_multicast, type=0x88cc)
        frame = eth / Raw(load=bytes(payload)) / Padding(b'\x00\x00\x00\x00')
        sleep(0.5)
        packet = PacketIn(buffer_id=UBInt32(1), total_len=UBInt16(len(frame)) + len(Ether() / IP() / TCP()),
                          reason=PacketInReason.OFPR_NO_MATCH, data=bytes(frame), in_port=UBInt16(1))
        sock.sendall(packet.pack())
        data = sock.recv(4096)
        print(unpack(data))
        scapy_lldp = Ether(data)
        scapy_lldp.show()
        lldp_packet = LLDP(scapy_lldp.payload)
        print(lldp_packet.chassis)
        print(lldp_packet.TTL)



    finally:
        print('closing socket')
        sock.close()
