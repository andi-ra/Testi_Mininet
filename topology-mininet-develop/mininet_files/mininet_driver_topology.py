import time

from mininet.node import RemoteController, OVSSwitch
import networkx as nx
from matplotlib import pyplot as plt
from mininet.net import Mininet
from mininet.topo import Topo


class MininetTopoFromNxGraph(Topo):
    """Construct a mininet topology from a nx graph."""

    def build(self, G: nx.Graph = None) -> None:
        """Processa il grafo G e costruisci una topologia

        :param G: Grafo con le info di rete embedded
        """
        switches = {}
        hosts = {}
        for node in G.nodes(data=True):
            name = str(node[0])
            switches[name] = self.addSwitch("s" + name)
            hosts[name] = self.addHost("h" + name)
            self.addLink(switches[name], hosts[name])

        for edge in G.edges(data=True):
            self.addLink(switches[str(edge[0])], switches[str(edge[1])])


topos = {'mytopo': (lambda: MininetTopoFromNxGraph())}

if __name__ == '__main__':
    N = 20
    p = 0.1
    G = nx.erdos_renyi_graph(N, p)
    # Creazione del dictionary temporaneo per aggiungere i nodi

    # Plot del grafo
    nx.draw(G, with_labels=True)
    plt.show()
    print(G.edges)
    topo = MininetTopoFromNxGraph(G)
    net = Mininet(topo=topo,
                  controller=lambda name: RemoteController(name, ip='127.0.0.1'),
                  switch=OVSSwitch,
                  )
    net.start()
    for switch in net.switches:
        br_list = str(switch.cmd("ovs-vsctl list-br")).strip("\r").split("\n")
        br_list = [bridge.strip("\r") for bridge in br_list]
        for bridge in br_list:
            result = switch.cmd("ovs-vsctl set Bridge {0} stp_enable=true".format(bridge))

    host = net.getNodeByName("h7")
    result = host.cmd("ifconfig")
    print(result)

    net.pingAll(timeout=0.5)
    net.pingAll(timeout=0.01)

    net.stop()
