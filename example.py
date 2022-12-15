import os
from vt_graph_util import *
from dotenv import load_dotenv

load_dotenv()

# VT_API_KEY from .env
API_KEY = os.getenv('VT_API_KEY')

graph = Graph('gfb501791002a40f9b10e897399742eb8f4793c1d2b8a47d49ab8f0cb7149927e', API_KEY)
json_data = graph.graph_to_json()   # { 'nodes': nodes, 'links': links }
nodes = json_data['nodes']
links = json_data['links']

for group_id, group in graph.groups.items():
    if group.entity_type == 'file' and len(group.nodes) < 5:
        graph.expand(group_id, 'contacted_ips', 10, API_KEY)
    elif group.entity_type == 'ip_address' and len(group.nodes) > 10:
        graph.detail(group_id, 'link', False)

json_data = graph.graph_to_json()
nodes = json_data['nodes']
links = json_data['links']