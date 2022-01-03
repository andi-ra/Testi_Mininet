"""
File in cui ci metto delle funzioni di utility pe poter lavorare meglio con i grafi
"""
import json

import networkx
from networkx.readwrite import json_graph


def save(G: networkx.Graph, filename: str):
    data1 = json_graph.node_link_data(G)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data1, f, ensure_ascii=False, indent=4)
