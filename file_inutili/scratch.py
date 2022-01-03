import networkx as nx
import matplotlib.pyplot as plt
from mininet_driver_topology import MininetTopoFromNxGraph
from mininet_driver_topology.net import Mininet
import itertools
import socket
import struct
import random

N, L = 10, 1
G = nx.barabasi_albert_graph(N, L)
nx.draw(G, with_labels=True)
plt.show()
topo = MininetTopoFromNxGraph(G)
net = Mininet(topo=topo)
net.start()
for host in net.hosts:
    globals()['%s' % host] = net.get(host.name)
for switch in net.hosts:
    globals()['%s' % switch] = net.get(switch.name)
for host in net.hosts:
    lista = [iface for iface in host.intfNames() if iface]
for host in net.hosts:
    for iface in host.intfList():
        if str(host.IP(intf=iface)) == str(None):
            host.setIP(ip=socket.inet_ntoa(struct.pack('>I', random.randint(0x0a000000, 0x0afffffe))), intf=iface,
                       prefixLen=8)
for host in net.hosts:
    for iface in host.intfList():
        print("iface {0}: {1}".format(str(iface), str(host.IP(intf=iface))))
for host in net.hosts:
    for iface in host.intfList():
        print("iface {0}: {1}".format(str(iface), str(host.IP(intf=iface))))
for i, j in itertools.product(net.hosts, net.hosts):
    link = net.linksBetween(i, j)
    if link != []:
        print("Link between: {0} <-> {1}   : {2}".format(i, j, link))
for host in net.hosts:
    for iface in host.intfList():
        print("Host:{0}, iface {1} --->status Up={2}".format(host, iface, iface.status()))

for i, j in itertools.product(net.hosts, net.hosts):
    link = net.linksBetween(i, j)
    if link != []:
        net.ping([i, j], timeout=0.1)

for host in net.hosts:
    host.sendInt()

for host in net.hosts:
    host.monitor(timeoutms=100)

###In caso di assertion error
# h1.sendInt()
# h1.monitor()
