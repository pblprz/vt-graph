import requests

SUPPORTED_NODE_TYPES = [
    "file",
    "url", 
    "domain", 
    "ip_address",
    "whois",
    "ssl_cert",
    "collection",
    "reference"
]

NODE_EXPANSIONS: dict[str, str] = {
    "file": [
        "bundled_files",
        "collections",
        "compressed_parents",
        "contacted_domains",
        "contacted_ips",
        "contacted_urls",
        "dropped_files",
        "email_parents",
        "email_attachments",
        "embedded_domains",
        "embedded_urls",
        "embedded_ips",
        "execution_parents",
        "itw_domains",
        "itw_urls",
        "itw_ips",
        "overlay_parents",
        "overlay_children",
        "pcap_parents",
        "pe_resource_parents",
        "pe_resource_children",
        "references",
        "similar_files",
        "urls_for_embedded_js"
    ],
    "url": [
        "downloaded_files",
        "last_serving_ip_address",
        "network_location",
        "redirecting_urls",
        "contacted_domains",
        "contacted_ips",
        "redirects_to",
        "urls_related_by_tracker_id",
        "communicating_files",
        "referrer_files",
        "embedded_js_files",
        "collections",
        "references"
    ],
    "domain": [
        "immediate_parent",
        "parent",
        "communicating_files",
        "downloaded_files",
        "referrer_files",
        "resolutions",
        "siblings",
        "subdomains",
        "urls",
        "historical_ssl_certificates",
        "historical_whois",
        "caa_records",
        "cname_records",
        "mx_records",
        "ns_records",
        "soa_records",
        "collections",
        "references"
    ],
    "ip_address": [
        "communicating_files",
        "downloaded_files",
        "referrer_files",
        "resolutions",
        "urls",
        "historical_ssl_certificates",
        "historical_whois",
        "collections",
        "references"
    ],
    "reference": [
        "files",
        "domains",
        "urls",
        "ip_addresses",
        "collections"
    ],
    "collection": [
        "files",
        "domains",
        "ip_addresses",
        "urls",
        "references"
    ],
    "whois": ["network_location"],
    "ssl_cert": []
}

class Node(object):
    '''
    A node can be an entity or relationship node.

    Args:
    - entity_id (str): node identifier
    - entity_type (str): node type (file, domain, ip_address, url, relationship...)
    - text (str, optional): node label
    - entity_attributes (dict, optional): node attributes from VT
    - links (set[Link], optional): links from or to the node

    Properties:
    - entity_id (str): node identifier
    - entity_type (str): node type (file, domain, ip_address, url, relationship...)
    - text (str): node label
    - entity_attributes (dict): node attributes from VT
    - links (set[Link]): links from the node
    - links_in (set[Link]): links to the node
    - has_detections (bool): whether node is detected by any AV
    - is_root (bool): whether node is root
    - rel_type (str): type of relationship node. Exception if it is not a relationship node
    - children (dict[str, set]): dict with a set of all children for each relationship
    - parents (dict[str, set]): dict with a set of all parents for each relationship
    '''

    def __init__(self, entity_id: str, entity_type: str, text='', entity_attributes: dict=None, links: set['Link']=None):
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.text = text
        self.links: set['Link'] = set()
        self.links_in: set['Link'] = set()
        self.entity_attributes = entity_attributes or {}
        if self.entity_type == 'file' and 'type_tag' not in self.entity_attributes:
            self.entity_attributes['type_tag'] = None
        elif self.entity_type == 'ip_address' and 'country' not in self.entity_attributes:
            self.entity_attributes['country'] = 'ZZ'
        if links != None: self.add_links(links)

    @property
    def is_root(self):
        '''
        Whether node is root.
        '''
        return 'ROOT' in self.text.upper()

    @property
    def has_detections(self):
        '''
        Whether node is detected by any AV.
        '''
        return self.entity_attributes['has_detections'] > 0 if 'has_detections' in self.entity_attributes else False

    @property
    def rel_type(self):
        '''
        Type of relationship node. Exception if it is not a relationship node.
        '''
        if self.entity_type == 'relationship':
            if len(self.links) > 0: return list(self.links)[0].link_type
            elif len(self.links_in) > 0: return list(self.links_in)[0].link_type
            else: raise Exception('Relationship node should always have links')
        else: raise Exception('This node is not a relationship node')

    @property
    def children(self):
        '''
        Dict with a set of all children for each relationship.
        '''
        children: dict[str, set] = {}
        for link in self.links:
            if link.link_type not in children:
                children[link.link_type] = set()
            children[link.link_type].add(link.target)
        return children
    
    @property
    def parents(self):
        '''
        Dict with a set of all parents for each relationship.
        '''
        parents: dict[str, set] = {}
        for link in self.links_in:
            if link.link_type not in parents:
                parents[link.link_type] = set()
            parents[link.link_type].add(link.source)
        return parents

    def __str__(self):
        return "%s" % (self.entity_id)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return isinstance(other, Node) and self.entity_id == other.entity_id

    def __hash__(self):
        return hash(self.entity_id)

    def add_link(self, link: 'Link'):
        '''
        Add link to the node. The current node must be source or target.
        '''
        if self.entity_id == link.source:
            self.links.add(link)
        elif self.entity_id == link.target:
            self.links_in.add(link)

    def add_links(self, links: set['Link']):
        '''
        Add links to the node. The current node must be source or target.
        '''
        for link in links:
            self.add_link(link)

class Group(Node):
    '''
    A group is a node with nodes.

    Args:
    - entity_id (str): node identifier
    - entity_type (str): node type (file, domain, ip_address, url, relationship...)
    - text (str, optional): node label
    - entity_attributes (dict, optional): node attributes from VT
    - nodes (dict[str, Node], optional): nodes in the group
    - links (set[Link], optional): links from or to the node

    Properties:
    - entity_id (str): node identifier
    - entity_type (str): node type (file, domain, ip_address, url, relationship...)
    - text (str): node label
    - entity_attributes (dict): node attributes from VT
    - nodes (dict[str, Node]): nodes in the group
    - supergroup (str): supergroup or parent of the current group
    - subgroups (set[str]): subgroups or children of the current group 
    - links (set[Link]): links from the node
    - links_in (set[Link]): links to the node
    - has_detections (bool): whether node is detected by any AV
    - is_root (bool): whether node is root
    - rel_type (str): type of relationship node. Exception if it is not a relationship node
    - children (dict[str, set]): dict with a set of all children groups for each relationship
    - nodes_children (dict[str, set]): dict with a set of all children nodes for each relationship 
    - parents (dict[str, set]): dict with a set of all parents for each relationship
    '''

    def __init__(self, entity_id: str, entity_type: str, text='', entity_attributes: dict=None, nodes: dict[str, Node]=None, links: set['Link']=None):
        super().__init__(entity_id, entity_type, text, entity_attributes, links)
        self.nodes = nodes or {}
        self.supergroup: str = None
        self.subgroups: set[str] = set()
        node_0 = list(self.nodes.values())[0]
        if self.entity_type == 'ip_address' and not all(node.entity_attributes['country'] == node_0.entity_attributes['country'] for node in self.nodes.values()):
            self.entity_attributes.pop('country')
        self.recalculate_img()

    @property
    def has_detections(self):
        '''
        Whether node is detected by any AV.
        '''
        for node in self.nodes.values():
            if node.has_detections:
                return True
        return False

    @property
    def rel_type(self):
        '''
        Type of relationship node. Exception if it is not a relationship node.
        '''
        if self.entity_type == 'relationship':
            if len(self.nodes_children.keys()) > 0: return list(self.nodes_children.keys())[0]
            elif len(self.links_in) > 0: return list(self.links_in)[0].link_type
            else: raise Exception('Relationship node should always have links')
        else: raise Exception('This node is not a relationship node')

    @property
    def nodes_children(self):
        '''
        Dict with a set of all children nodes for each relationship.
        '''
        children: dict[str, set] = {}
        for node in self.nodes.values():
            for link in node.links:
                if link.link_type not in children:
                    children[link.link_type] = set()
                if link.target not in children[link.link_type]:
                    children[link.link_type].add(link.target)
        return children

    def has_node(self, node: str):
        '''
        Whether group has the given node.
        '''
        return node in self.nodes.keys()

    def add_node(self, node: Node):
        '''
        Add node to current group.
        '''
        self.nodes[node.entity_id] = node
        self.recalculate_img()

    def add_nodes(self, nodes: set[Node]):
        '''
        Add nodes to current group.
        '''
        for node in nodes:
            self.add_node(node)

    def add_subgroup(self, group: 'Group'):
        '''
        Add group to current group as subgroup and current group to group as supergroup.
        '''
        group.supergroup = self.entity_id
        self.subgroups.add(group.entity_id)

    def add_supergroup(self, group: 'Group'):
        '''
        Add group to current group as supergroup and current group to group as subgroup.
        '''
        self.supergroup = group.entity_id
        group.subgroups.add(self.entity_id)

    def recalculate_img(self):
        '''
        Recalculate the image. It must be done when the group changes.
        '''
        node_0 = list(self.nodes.values())[0]
        if self.entity_type == 'relationship':
            if all(node.rel_type == node_0.rel_type for node in self.nodes.values()):
                self.entity_attributes['img'] = 'relationships/' + node_0.rel_type
            else: self.entity_attributes['img'] = 'relationships/group_black'
        elif self.entity_type == 'domain':
            self.entity_attributes['img'] = 'node_types/domain_icon'
        elif self.entity_type == 'whois':
            self.entity_attributes['img'] = 'node_types/whois'
        elif self.entity_type == 'ssl_cert':
            self.entity_attributes['img'] = 'node_types/ssl_cert'
        elif self.entity_type == 'collection':
            self.entity_attributes['img'] = 'node_types/collection'
        elif self.entity_type == 'url':
            self.entity_attributes['img'] = 'node_types/' + ('red' if self.has_detections else 'black') + '-url'
        elif self.entity_type == 'file':
            try:
                if all(node.entity_attributes['type_tag'] == node_0.entity_attributes['type_tag'] for node in self.nodes.values()):
                    type_tag = node_0.entity_attributes['type_tag']
                    if type_tag in (None, 'php', 'cap', 'powershell'): type_tag = 'file'
                    elif type_tag == 'text': type_tag = 'txt'
                    elif type_tag == 'c': type_tag = 'cpp'
                    elif type_tag == 'javascript': type_tag = 'js'
                    elif type_tag == 'vba': type_tag = 'vb'
                    self.entity_attributes['img'] = 'node_types/' + ('red' if self.has_detections else 'black') + '-' + type_tag
                else:
                    self.entity_attributes['img'] = 'relationships/group_' + ('red' if self.has_detections else 'black')
            except:
                self.entity_attributes['img'] = 'relationships/group_' + ('red' if self.has_detections else 'black')
        elif self.entity_type == 'ip_address':
            if all(node.entity_attributes['country'] == node_0.entity_attributes['country'] for node in self.nodes.values()):
                self.entity_attributes['img'] = 'flags/' + node_0.entity_attributes['country'].lower()
            else:
                self.entity_attributes['img'] = 'relationships/group_' + ('red' if self.has_detections else 'black')
        else:
            self.entity_attributes['img'] = 'relationships/group_' + ('red' if self.has_detections else 'black')

    def __str__(self):
        return f'Group: {{ ID: {self.entity_id}, Type: {self.entity_type}, Nodes: {list(self.nodes.keys())}, Supergroup: {self.supergroup}, Subgroups: {list(self.subgroups)} }}'

class Link(object):
    '''
    A link can be: Group -> Relationship or Relationship -> Group.

    Args:
    - source (str): source node
    - target (str): target node
    - link_type (str): link type (dropped_files, itw_urls...)
    - style (bool, optional): edge style -> true (default), false (dashed)
    '''

    def __init__(self, source: str, target: str, link_type: str, style: bool=True):
        self.source = source
        self.target = target
        self.link_type = link_type
        self.style = style

    def __str__(self):
        return self.source[:40] + ' -- ' + self.link_type + ' -> ' + self.target[:40]

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return isinstance(other, Link) and self.source == other.source and self.target == other.target and self.link_type == other.link_type

    def __hash__(self):
        return hash(self.source + self.target + self.link_type)

class Graph(object):
    '''
    Graph class.

    Args:
    - graph_id (str): id of the VT Graph
    - api_key (str): API KEY used in VT

    Attributes:
    - nodes (dict[str=node_id, Node]): nodes from vt_graph
    - groups (dict[str=group_id, Group]): groups for frontend
    - links (set[Link]): links for frontend
    '''
    def __init__(self, graph_id: str, api_key: str):
        self.graph_id = graph_id
        self.nodes: dict[str, Node] = {}
        self.groups: dict[str, Group] = {}
        # self.links: set[Link] = set()   # It is not necessary

        data = load_graph(graph_id, api_key)
        self.nodes, _ = json_to_nodes(data)
        self.nodes_to_groups()

    @property
    def links(self):
        '''
        Returns a set with all links for frontend.
        '''
        links: set[Link] = set()
        for group in self.groups.values():
            for link in group.links:
                links.add(link)
        return links

    def groups_to_json(self):
        '''
        Returns groups in JSON format for frontend.
        '''
        json_nodes = []
        for g in self.groups.values():
            nodes = list(g.nodes.keys())
            attributes = g.entity_attributes
            attributes['has_detections'] = g.has_detections
            if g.entity_type == 'relationship': attributes['rel_type'] = g.rel_type
            json_nodes.append({ 'id': g.entity_id, 'type': g.entity_type, 'text': g.text, 'nodes': nodes, 'attributes': attributes, 'parent': g.supergroup, 'children': list(g.subgroups) })
        return json_nodes

    def links_to_json(self):
        '''
        Returns links in JSON format for frontend.
        '''
        json_links = []
        for l in self.links:
            json_links.append({ 'source': l.source, 'target': l.target, 'type': l.link_type, 'style': l.style })
        return json_links

    def graph_to_json(self):
        '''
        Returns graph (groups and links) in JSON format for frontend.
        '''
        return { 'nodes': self.groups_to_json(), 'links': self.links_to_json() }

    def __str__(self):
        return f'Graph:\n - Groups: {self.groups.values()}\n - Links: {self.links}'

    def get_node(self, node_id: str):
        '''
        Get Node class for given node_id.
        '''
        return self.nodes[node_id]

    def get_nodes(self, node_ids: set[str]):
        '''
        Get Node classes for given node_ids.
        '''
        nodes = set()
        for id in node_ids:
            nodes.add(self.get_node(id))
        return nodes

    def get_group(self, group_id: str):
        '''
        Get Group class for given group_id.
        '''
        return self.groups[group_id]

    def get_groups(self, group_ids: set[str]):
        '''
        Get Group classes for given group_ids.
        '''
        groups = set()
        for id in group_ids:
            groups.add(self.get_group(id))
        return groups

    def add_node(self, node: Node):
        '''
        Add group to graph.
        '''
        self.nodes[node.entity_id] = node

    def add_group(self, group: Group):
        '''
        Add group to graph.
        '''
        self.groups[group.entity_id] = group

    def delete_nodes(self, group: Group, nodes: set[Node]):
        '''
        Delete nodes from group and supergroups recursively.
        '''
        for node in nodes:
            group.nodes.pop(node.entity_id)
        if group.supergroup != None:
            self.delete_nodes(self.get_group(group.supergroup), nodes)

    def delete_group(self, group: Group):
        '''
        Delete group from graph.
        '''
        self.groups.pop(group.entity_id)
        if group.supergroup != None:
            parent = self.get_group(group.supergroup)
            self.delete_nodes(parent, set(group.nodes.values()))
            parent.subgroups.discard(group.entity_id)
            # If parent has one single child, delete parent and grandpa acts as parent
            if len(parent.subgroups) == 1:
                sibling = self.get_group(parent.subgroups.pop())
                sibling.supergroup = parent.supergroup
                if parent.supergroup != None:
                    grandpa = self.get_group(parent.supergroup)
                    grandpa.subgroups.discard(parent)
                    grandpa.subgroups.add(sibling)
                self.groups.pop(parent.entity_id)

    def _detail(self, group_id: str, by, separate: bool=False):
        '''
        Detail a group creating subgroups according to the given function.\n
        For example: by = lambda x, y: x.has_detections == y.has_detections

        Args:
        - group_id (str): id of group to be detailed
        - by (function(Group, Group) => bool): function used for grouping
        - separate (bool, optional): true -> separate new groups from current group
        '''
        group = self.get_group(group_id)
        nodes_left = set(group.nodes.copy().values())
        new_groups: list[Group] = []
        while len(nodes_left) > 0:
            n1 = nodes_left.pop()
            nodes_left_2 = nodes_left.copy()
            equal_nodes = set([n1])
            while len(nodes_left_2) > 0:
                n2 = nodes_left_2.pop()
                if by(n1, n2):
                    equal_nodes.add(n2)
                    nodes_left.remove(n2)

            if len(equal_nodes) == len(group.nodes): return None

            entity_id = n1.entity_id if len(equal_nodes) == 1 else str(abs(hash(frozenset(equal_nodes))))
            text = n1.text if len(equal_nodes) == 1 else ''
            entity_attributes = n1.entity_attributes if len(equal_nodes) == 1 else {}
            nodes: dict[str, Node] = {}
            for node in equal_nodes:
                nodes[node.entity_id] = node
            new_group = Group(entity_id, n1.entity_type, text, entity_attributes, nodes)
            if not separate:
                group.add_subgroup(new_group)
            self.add_group(new_group)
            new_groups.append(new_group)
        if separate:
            self.delete_group(group)

        self.update_links()
        return new_groups

    def detail(self, group_id: str, by: str, separate: bool=False):
        '''
        Detail a group creating subgroups according to the given function.\n

        Args:
        - group_id (str): id of group to be detailed
        - by (str): function used for grouping ('link', 'type', 'detections', 'single')
        - separate (bool, optional): true -> separate new groups from current group
        '''
        group = self.get_group(group_id)
        new_groups = None
        if len(group.subgroups) == 0:
            f = None
            if by == 'link':
                f = lambda x, y: self._equal_links(x, y)
            elif by == 'type':
                if group.entity_type == 'file':
                    f = lambda x, y: x.entity_attributes['type_tag'] == y.entity_attributes['type_tag']
                elif group.entity_type == 'ip_address':
                    f = lambda x, y: x.entity_attributes['country'] == y.entity_attributes['country']
                elif group.entity_type == 'custom':
                    f = lambda x, y: x.entity_type == y.entity_type if (x.entity_type != 'relationship' or y.entity_type != 'relationship') else x.rel_type == y.rel_type
            elif by == 'detections':
                f = lambda x, y: x.has_detections == y.has_detections
            else: f = lambda x, y: x.entity_id == y.entity_id
            if f == None: return None
            new_groups = self._detail(group_id, f, separate)
            if new_groups == None: return None
        else:
            for delete_group in group.subgroups:
                self.groups.pop(delete_group)
            group.subgroups.clear()
            new_groups = group
        
        self.update_links()
        return new_groups

    def _expand(self, group_id: str, relationship: str):
        '''
        Expand the given group using the given relationship from the initial JSON.

        Args:
        - group_id (str): id of the group to be expanded
        - relationship (str): relationship to be expanded
        '''
        # Get all children (for the given relationship) from all nodes in group
        group = self.get_group(group_id)
        children = group.nodes_children[relationship]

        # If there are no children -> finish
        if len(children) == 0:
            return None
        
        # Compare children with all groups
        for other_group in self.groups.values():
            if (group != other_group):
                shared = children.intersection(other_group.nodes.keys())
                if len(shared) != 0:
                    children = children.difference(shared)
        
        # If children is not empty, add link from the current node to the new group
        if len(children) > 0:
            child_0 = self.get_node(list(children)[0])
            group_type = child_0.entity_type
            if group_type == 'relationship':
                group_id = child_0.entity_id if len(children) == 1 else f"relationships_{relationship}_{group.entity_id.replace('.', '')}"
            else:
                group_id = child_0.entity_id if len(children) == 1 else str(abs(hash(frozenset(children))))
            text = child_0.text if len(children) == 1 else ''
            entity_attributes = child_0.entity_attributes if len(children) == 1 else {}
            nodes = {}
            for child in children:
                nodes[child] = self.get_node(child)
            new_group = Group(group_id, group_type, text, entity_attributes, nodes)
            self.groups[new_group.entity_id] = new_group
            self.update_links()
            return new_group
        else:
            self.update_links()
            return None

    def nodes_to_groups(self):
        '''
        Take self.nodes and calculate self.groups.
        '''
        nodes_left = list(self.nodes.keys())
        while len(nodes_left) > 0:
            node_0 = self.get_node(nodes_left[0])
            nodes_left.remove(node_0.entity_id)
            text = (node_0.entity_id if node_0.text == '' else node_0.text) + ' (root)'
            group = Group(node_0.entity_id, node_0.entity_type, text, node_0.entity_attributes, { node_0.entity_id: node_0 })
            stop = False
            for g in self.groups.copy().values():
                if group.entity_type == g.entity_type and group.nodes_children == g.nodes_children:
                    self.groups.pop(g.entity_id)
                    nodes = g.nodes
                    nodes[node_0.entity_id] = node_0
                    group_id = str(abs(hash(frozenset(nodes))))
                    text = group_id + ' (root)'
                    # print(nodes)
                    group = Group(group_id, node_0.entity_type, text, {}, nodes)
                    self.groups[group.entity_id] = group
                    stop = True
            new_groups = []
            while group != None and not stop:
                self.groups[group.entity_id] = group
                for relationship in group.nodes_children.keys():
                    new_group = self._expand(group.entity_id, relationship)
                    if new_group != None:
                        new_groups.append(new_group)
                        for node in new_group.nodes.keys():
                            nodes_left.remove(node)
                group = None if len(new_groups) == 0 else new_groups.pop(0)
        
        self.update_links()

    def grandchildren(self, node: Node):
        '''
        Dict with a set of all grandchildren for each relationship of the given node. 
        It is useful to "ignore" the relationship nodes.

        Args:
        - node (Node): given node

        Returns:
        - grandchildren (dict[str, set]): grandchildren of the given node
        '''
        grandchildren: dict[str, set] = {}
        for relationship, children in node.children.items():
            grandchildren[relationship] = set()
            for child in children:
                child = self.get_node(child)
                if relationship in child.children:
                    for grandchild in child.children[relationship]:
                        grandchildren[relationship].add(grandchild)
        return grandchildren

    def expand(self, group_id: str, relationship: str, limit: int, api_key: str):
        '''
        Expand the group looking for children in the given relationship. This function will be improved in the near future.

        Args:
        - group_id (str): id of the group to be expanded
        - relationship (str): relationship to be expanded
        - limit (int): max number of nodes for the given relationship
        - api_key (str): API KEY used in VT

        Returns:
        - rel_group (Group): new relationship group
        - target_group (Group): new group with the nodes obtained in the expansion
        '''
        group = self.get_group(group_id)
        # Relationship nodes are not abled to be expanded
        if group.entity_type == 'relationship': return None, None
        rel_nodes: set[Node] = set()
        target_nodes: set[Node] = set()
        rel_group = None
        target_group = None
        # If relationship is 'all': repeat for all relationships
        if relationship == 'all':
            rels = set(NODE_EXPANSIONS.values()) if group.entity_id == 'custom' else NODE_EXPANSIONS[group.entity_type]
            rel_groups = []
            target_groups = []
            for rel in rels:
                r, t = self.expand(group_id, rel, limit, api_key)
                rel_groups.append(r)
                target_groups.append(t)
            return rel_groups, target_groups
        else:
            # Expand the group expanding its nodes
            for node_id, node in group.nodes.items():
                if relationship in NODE_EXPANSIONS[node.entity_type]:
                    endpoint = node.entity_type + ('es' if node.entity_type == 'ip_address' else 's')
                    url = f"https://www.virustotal.com/api/v3/{endpoint}/{node_id}/{relationship}?limit={limit}"
                    headers = { "Accept": "application/json", "x-apikey": api_key }
                    response = requests.get(url, headers=headers)
                    if response.status_code != 200:
                        raise Exception(f'Error to expand relationship {relationship} in node {node_id}. Response code: {response.status_code}')
                    # print(response.json())
                    data_json = [] if 'data' not in response.json() or response.json()['data'] == None else response.json()['data']
                    # print(f'Node: {node_id} - Relationship: {relationship}  -->  {len(data_json)}')

                    # If there are nodes in data_json and node has not the given relationship or any of the nodes does not relate with it
                    if len(data_json) > 0 and (relationship not in node.children or any(n['id'] not in self.grandchildren(node)[relationship] for n in data_json)):
                        rel_node_id = f"relationships_{relationship}_{node_id.replace('.', '')}"
                        # If the node is already in the graph, don't create it again
                        if rel_node_id in self.nodes: 
                            rel_node = self.get_node(rel_node_id)
                        else: 
                            rel_node = Node(rel_node_id, 'relationship', '', {})
                            rel_link = Link(node_id, rel_node.entity_id, relationship)
                            node.add_link(rel_link)
                            rel_node.add_link(rel_link)
                            self.add_node(rel_node)
                        rel_nodes.add(rel_node)
                        for new_node in data_json:
                            entity_id = new_node['id']
                            # If the current node has not the given relationship or the new node does not relate with it
                            if (relationship not in node.children or entity_id not in self.grandchildren(node)[relationship]):
                                # If the new node is not in the graph, create it
                                if entity_id not in self.nodes:
                                    entity_type = new_node['type']
                                    if entity_type == 'resolution':
                                        entity_type = 'ip_address' if node.entity_type == 'domain' else 'domain'
                                    attributes = new_node['attributes'] if 'attributes' in new_node else {}
                                    if new_node['type'] == 'ip_address':
                                        try:
                                            attributes['country'] = new_node['attributes']['country']
                                        except:
                                            attributes['country'] = 'ZZ'
                                    elif new_node['type'] == 'file':
                                        try:
                                            attributes['type_tag'] = new_node['attributes']['type_tag']
                                        except:
                                            attributes['type_tag'] = None
                                    target_node = Node(entity_id, entity_type, '', attributes)
                                    self.add_node(target_node)
                                    target_nodes.add(target_node)
                                # If the new node is in the graph, don't create it again
                                else:
                                    target_node = self.get_node(entity_id)
                                target_link = Link(rel_node_id, entity_id, relationship)
                                rel_node.add_link(target_link)
                                target_node.add_link(target_link)

                        # This must be improved using something similar to: all(other_group.children) in new_group.children
                        # Instead of the both groups having exactly the same children
                        for n in self.nodes.values():
                            if n != rel_node and n.children == rel_node.children:
                                aux_link = Link(node_id, rel_node.entity_id, relationship)
                                if aux_link in node.links: node.links.remove(aux_link)
                                if rel_node in rel_nodes: rel_nodes.remove(rel_node)
                                for children in rel_node.children.values():
                                    for child in children:
                                        child = self.get_node(child)
                                        aux_link = Link(rel_node.entity_id, child.entity_id, relationship)
                                        if aux_link in child.links_in: child.links_in.remove(aux_link)
                                new_link = Link(node_id, n.entity_id, relationship)
                                node.add_link(new_link)
                                n.add_link(new_link)

            # Nodes to groups
            if len(target_nodes) > 0 or len(rel_nodes) > 0:
                rel_group_id = f"relationships_{relationship}_{group_id.replace('.', '')}" if len(rel_nodes) > 1 else list(rel_nodes)[0].entity_id
                # If relationship group is already in the graph, don't create it again
                if rel_group_id in self.groups:
                    rel_group = self.get_group(rel_group_id)
                    for r_node in rel_nodes:
                        if not rel_group.has_node(r_node.entity_id):
                            rel_group.add_node(r_node)
                else:
                    entity_attributes = list(rel_nodes)[0].entity_attributes if len(rel_nodes) == 1 else {}
                    nodes: dict[str, Node] = {}
                    for r_node in rel_nodes:
                        nodes[r_node.entity_id] = r_node
                    rel_group = Group(rel_group_id, 'relationship', '', entity_attributes, nodes)
                    self.add_group(rel_group)

                # Create the new target group. If the code enters here, there will always be a new target group
                if len(target_nodes) > 0:
                    target_group_id = list(target_nodes)[0].entity_id if len(target_nodes) == 1 else str(abs(hash(frozenset(target_nodes))))
                    text = list(target_nodes)[0].text if len(target_nodes) == 1 else ''
                    entity_attributes = list(target_nodes)[0].entity_attributes if len(target_nodes) == 1 else {}
                    nodes: dict[str, Node] = {}
                    for t_node in target_nodes:
                        nodes[t_node.entity_id] = t_node
                    target_group = Group(target_group_id, list(target_nodes)[0].entity_type, text, entity_attributes, nodes)
                    self.add_group(target_group)

            self.update_links()
            return rel_group, target_group

    def update_links(self):
        '''
        Update all links. It is a bit slower but is too much easier.
        '''
        self.links.clear()
        for group in self.groups.values():
            group.links.clear()
            group.links_in.clear()
        for group in self.groups.values():
            if len(group.subgroups) == 0:
                for link_type, targets in group.nodes_children.items():
                    for other_group in self.groups.values():
                        if len(other_group.subgroups) == 0 and other_group != group:
                            if all(n in targets for n in other_group.nodes.keys()):
                                new_link = Link(group.entity_id, other_group.entity_id, link_type)
                                group.add_link(new_link)
                                other_group.add_link(new_link)
                            elif any(n in targets for n in other_group.nodes.keys()):
                                new_link = Link(group.entity_id, other_group.entity_id, link_type, False)
                                group.add_link(new_link)
                                other_group.add_link(new_link)

    def custom_group(self, groups: list[str]):
        '''
        Create a new group with the groups given.

        Args:
        - groups (list[str]): list with all group ids

        Returns:
        - new_group (Group): new group created
        '''
        nodes: dict[str, Node] = {}
        for group_id in groups:
            self.separate_group(group_id)
            group = self.groups.pop(group_id)
            for subgroup_id in group.subgroups:
                self.groups.pop(subgroup_id)
            for node_id, node in group.nodes.items():
                nodes[node_id] = node
        node_0 = list(nodes.values())[0]
        entity_type = node_0.entity_type if all(node.entity_type == node_0.entity_type for node in nodes.values()) else 'custom'
        new_group = Group(str(abs(hash(frozenset(nodes.keys())))), entity_type, '', {}, nodes)
        self.add_group(new_group)
        self.update_links()
        return new_group

    def separate_group(self, group_id: str):
        '''
        Separate the given group from its parent.

        Args:
        - group (str): group id to be separated
        '''
        group = self.get_group(group_id)
        if group.supergroup != None:
            parent = self.get_group(group.supergroup)
            group.supergroup = None
            self.delete_nodes(parent, set(group.nodes.values()))
            parent.subgroups.discard(group.entity_id)
            if len(parent.subgroups) == 1:
                sibling = self.get_group(parent.subgroups.pop())
                sibling.supergroup = parent.supergroup
                if parent.supergroup != None:
                    grandpa = self.get_group(parent.supergroup)
                    grandpa.subgroups.remove(parent.entity_id)
                    grandpa.subgroups.add(sibling.entity_id)
                self.groups.pop(parent.entity_id)

    def _equal_links(self, n1: Node, n2: Node):
        '''
        Function used in detail function to detail by link.
        '''
        sources1 = set()
        targets1 = set()
        sources2 = set()
        targets2 = set()
        for link in n1.links:
            target = link.target
            for group in self.groups.values():
                if target in group.nodes and len(group.subgroups) == 0:
                    target = group.entity_id
            targets1.add(target)
        for link in n1.links_in:
            source = link.source
            for group in self.groups.values():
                if source in group.nodes and len(group.subgroups) == 0:
                    source = group.entity_id
            sources1.add(source)

        for link in n2.links:
            target = link.target
            for group in self.groups.values():
                if target in group.nodes and len(group.subgroups) == 0:
                    target = group.entity_id
            targets2.add(target)
        for link in n2.links_in:
            source = link.source
            for group in self.groups.values():
                if source in group.nodes and len(group.subgroups) == 0:
                    source = group.entity_id
            sources2.add(source)

        return sources1 == sources2 and targets1 == targets2

    def path(self, group_ids: list[str], predecessors=True, successors=True, intersection=False):
        '''
        Calculate the target path of the given groups.

        Args:
        - group_ids (list[str]): group ids
        - predecessors (bool, optional): whether it includes the predecessors (default = True)
        - successors (bool, optional): whether it includes the successors (default = True)
        - intersection (bool, optional): whether it intersects the target path of the given groups (default = False)

        Returns:
        - target_nodes (set[str]): ids of the target nodes
        '''
        target_nodes: set[str] = None
        nodes: set[str] = set()
        for group_id in group_ids:
            nodes.clear()
            if predecessors: nodes = self._path(group_id, False)
            if successors: nodes = nodes.union(self._path(group_id))
            if intersection: target_nodes = nodes.copy() if target_nodes == None else target_nodes.intersection(nodes)
            else: target_nodes = nodes.copy() if target_nodes == None else target_nodes.union(nodes)

        return target_nodes

    def _path(self, group_id: str, successors=True):
        '''
        Help path function.
        '''
        # Most important relationship for target path
        target_relationships = ['communicating_files', 'downloaded_files', 'referrer_files', 'resolutions', 'urls', 'parent',
                                'contacted_domains', 'contacted_ips', 'network_location', 'redirecting_urls', 'redirects_to',
                                'bundled_files', 'compressed_parents', 'contacted_urls', 'dropped_files', 'email_attachments',
                                'email_parents', 'embedded_domains', 'embedded_ips', 'embedded_urls', 'pe_resource_parents',
                                'itw_domains', 'itw_ips', 'itw_urls', 'overlay_parents', 'pcap_parents', 'execution_parents']

        groups: dict[str, Group] = {}
        target_nodes: set[str] = set()
        group = self.get_group(group_id)
        groups[group_id] = group
        for node in group.nodes.values():
            target_nodes.add(node.entity_id)
            previous_nodes: set[str] = set()
            while target_nodes != previous_nodes:
                new_nodes = set(target_nodes.copy() - previous_nodes.copy())
                previous_nodes = target_nodes.copy()
                for target_node in new_nodes:
                    if successors:
                        for link in self.get_node(target_node).links:
                            if link.link_type in target_relationships:
                                target_nodes.add(link.target)
                    else:
                        for link in self.get_node(target_node).links_in:
                            if link.link_type in target_relationships:
                                target_nodes.add(link.source)

        return target_nodes

    def neighbours(self, group_ids: list[str], predecessors=True, successors=True, intersection=False):
        '''
        Calculate the neighbours of the given groups.

        Args:
        - group_ids (list[str]): group ids
        - predecessors (bool, optional): whether it includes the predecessors (default = True)
        - successors (bool, optional): whether it includes the successors (default = True)
        - intersection (bool, optional): whether it intersects the neighbours of the given groups (default = False)

        Returns:
        - target_nodes (set[str]): ids of the target nodes
        '''
        target_nodes: set[str] = None
        nodes: set[str] = set()
        for group_id in group_ids:
            nodes.clear()
            if predecessors: nodes = self._neighbours(group_id, False)
            if successors: nodes = nodes.union(self._neighbours(group_id))
            if intersection: target_nodes = nodes.copy() if target_nodes == None else target_nodes.intersection(nodes)
            else: target_nodes = nodes.copy() if target_nodes == None else target_nodes.union(nodes)

        return target_nodes

    def _neighbours(self, group_id: str, successors=True):
        '''
        Help neighbours function.
        '''
        target_nodes: set[str] = set()
        group = self.get_group(group_id)
        for node in group.nodes.values():
            target_nodes.add(node.entity_id)
            if successors:
                for link in node.links:
                    target_nodes.add(link.target)
                    if node.entity_type != 'relationship':
                        target = self.get_node(link.target)
                        for link_2 in target.links:
                            target_nodes.add(link_2.target)
            else:
                for link in node.links_in:
                    target_nodes.add(link.source)
                    if node.entity_type != 'relationship':
                        target = self.get_node(link.source)
                        for link_2 in target.links_in:
                            target_nodes.add(link_2.source)

        return target_nodes

def json_to_nodes(data_json: dict):
    '''
    Parse VT Graph JSON to nodes (Node class).

    Args:
    - data_json (dict): JSON with the data

    Returns:
    - nodes (dict[str=node_id, Node]): dict with all the nodes
    '''
    # All nodes from JSON {node_id: Node}
    nodes: dict[str, Node] = {}
    links = set()

    # Save links (relationships)
    for link in data_json['links']:
        new_link = Link(link['source'], link['target'], link['connection_type'])
        links.add(new_link)

    # Save nodes
    for node in data_json['nodes']:
        text = node['text'] if 'text' in node else ''
        attributes = node['entity_attributes'] if 'entity_attributes' in node else {}
        if node['type'] == 'ip_address':
            try:
                attributes['country'] = node['entity_attributes']['country']
            except:
                attributes['country'] = 'ZZ'
        elif node['type'] == 'file':
            try:
                attributes['type_tag'] = node['entity_attributes']['type_tag']
            except:
                attributes['type_tag'] = None
        nodes[node['entity_id']] = Node(node['entity_id'], node['type'], text, attributes, links)

    return nodes, links

def load_graph(graph_id: str, api_key: str):
    '''
    Load the graph using the given VirusTotal graph ID.

    Args:
    - graph_id (str): VirusTotal Graph ID
    - api_key (str): API KEY used in VT

    Returns:
    - data_json (dict): imported graph using JSON format
    '''
    # Get graph JSON from VT
    url = f"https://www.virustotal.com/api/v3/graphs/{graph_id}"
    headers = { "x-apikey": api_key }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        raise Exception(f'Error to find graph with id: {graph_id}. Response code: {response.status_code}')
    try:
        data_json = response.json()['data']['attributes']
    except:
        raise Exception(f'Unexpected error in json structure at graph: {graph_id}')
    return data_json