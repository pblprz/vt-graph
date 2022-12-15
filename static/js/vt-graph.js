// Variables necesarias
const selected_nodes = new Set();
const highlightNodes = new Set();
const highlightLinks = new Set();
let hoverNode = null;

/**
 * Objeto principal de VT Graph.
 */
class Node {
    /**
     * Constructor de la clase Node.
     * @param {String} id ID del grupo actual
     * @param {String} type Tipo del grupo actual
     * @param {String} text Texto adicional
     * @param {Set<String>} nodes Nodos que pertenecen al grupo actual
     * @param {{}} attributes Atributos del nodo en VT Graph
     * @param {Node} parent Grupo del que el grupo actual es subgrupo
     * @param {Set<Node>} children Subgrupos del grupo actual
     */
    constructor(id, type, text = '', nodes, attributes, parent = null, children = new Set()) {
        this.id = id;
        this.type = type;
        this.text = text;
        this.is_root = text.toUpperCase().includes('ROOT');
        this.nodes = new Set(nodes);
        if (type === 'relationship' && nodes.size > 0) this.name = attributes.rel_type;
        else if (text !== '') this.name = text;
        else this.name = id;
        this.parent = parent;
        this.children = new Set(children);
        this.attributes = attributes || {};
        this.update_img();
    }

    get has_detections() {
        return 'has_detections' in this.attributes ? this.attributes.has_detections : false;
    }

    get color() { 
        return this.has_detections && this.children.size === 0 && (this.type == 'ip_address' || this.type == 'domain') ? 'rgba(255, 0, 0, 0.4)' : 'transparent';
    }

    get val() {
        let val = 0;
        this.children.forEach(child => {
            val += child.val;
        });
        return val === 0 ? 1 : val * 2;
    }

    update_img() {
        const img = new Image();
        let str = '../static/vt_graph_icons/' + this.attributes.img + '.png';
        img.onerror = () => { 
            img.src = '../static/vt_graph_icons/node_types/' + (this.has_detections ? 'red' : 'black') + '-file.png';
        };
        img.src = str;
        this.attributes.img = img;
    }

}

/**
 * Objeto que une los distintos nodos mediante una relación.
 */
class Link {
    /**
     * Constructor de la clase Link
     * @param {String} source Nodo fuente
     * @param {String} target Nodo destino
     * @param {String} type Relación
     * @param {Boolean} style Indica si la arista es continua (true) o discontinua (false)
     */
    constructor(source, target, type, style=true) {
        this.source = source;
        this.target = target;
        this.type = type;
        this.style = style;
    }
}

/**
 * Curva los links que se solapan.
 * @param {Set<Link>|[Link]} links Links del grafo
 */
function curve_links(links) {
    links.forEach(l1 => {
        l1.curvature = 0;
        links.forEach(l2 => {
            if (l1.source === l2.target && l1.target === l2.source) {
                l1.curvature = 0.5;
            }
        });
    });
}

/**
 * Devuelve la fuerza que permite el agrupamiento.
 * @param {Number} NODE_R Constante usada para el radio de los nodos
 * @returns 
 */
function grouping(NODE_R) {
    let nodes;
    function force() {
        nodes.forEach(node => {
            if (node.parent !== null) {
                const parent = node.parent;
                const angle = 2*Math.PI/parent.children.size;
                const radius = Math.sqrt(node.val) * NODE_R;
                const parent_radius = Math.sqrt(parent.val) * NODE_R;
                // Visualizamos los subgrupos en una circunferencia para que estén equiespaciados
                if (!('aux' in parent)) {
                    parent.aux = 0;
                }
                if (parent.aux !== parent.children.size || !('cont' in node)) {
                    parent.aux = 0;
                    parent.children.forEach(child => {
                        child.cont = parent.aux;
                        parent.aux += 1;
                    });
                }
                const x_final = parent.x + (0.9*(parent_radius-radius)*Math.cos(angle*node.cont));
                const y_final = parent.y + (0.9*(parent_radius-radius)*Math.sin(angle*node.cont));
                node.vx = x_final - node.x;
                node.vy = y_final - node.y;
            }
        })
    }
    force.initialize = n => nodes = n;
    return force;
}

/**
 * Agrupa los nodos seleccionados.
 * @param {Set<Node>} selected_nodes Nodos seleccionados que serán agrupados
 * @param {*} Graph Grafo a modificar
 */
async function group(selected_nodes, Graph) {
    if (selected_nodes.size < 2) return;
    const group_ids = [];
    selected_nodes.forEach(node => {
        group_ids.push(node.id);
    });
    let request = '/custom_group?';
    selected_nodes.forEach(node => {
        request += 'group_id=' + node.id + '&';
    });
    let response = await fetch(request.slice(0, request.length-1), {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
    });
    console.log(response);
    try {
        let json = await response.json();
        console.log(json);
        json_to_graph(json, Graph);
        selected_nodes.clear();
    } catch { console.log("Error en GROUP") }
}

/**
 * Separa el subgrupo actual de su padre.
 * @param {Node} node Subgrupo que será separado de su grupo padre
 * @param {*} Graph Grafo a modificar
 */
async function separate_groups(node, Graph) {
    let response = await fetch(`/separate_group?group_id=${node.id}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
    });
    console.log(response);
    try {
        let json = await response.json();
        console.log(json);
        json_to_graph(json, Graph);
    } catch { console.log("Error en SEPARATE") }
}

/**
 * Detalla el grupo actual según el criterio dado, es decir, genera subgrupos de dicho grupo.
 * @param {Node} node Grupo que será detallado
 * @param {*} Graph Grafo a modificar
 * @param {String} by Criterio seguido para detallar el grupo
 * @param {Boolean} separate Indica si separar los subgrupos del padre o dejarlos dentro de él
 */
async function detail(node, Graph, by, separate) {
    let response = await fetch(`/detail?group_id=${node.id}&by=${by}&separate=${separate}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
    });
    console.log(response);
    try {
        let json = await response.json();
        console.log(json);
        if (node.children.size === 0) json_to_graph(json, Graph, node, true);
        else json_to_graph(json, Graph, node);
    } catch { console.log("Error en DETAIL") }
}

/**
 * Busca nodos que se relacionen con el grupo actual en la relación dada.
 * @param {Node} node Grupo que será "expandido"
 * @param {*} Graph Grafo a modificar
 * @param {String} relationship Relación en la que se buscarán los nuevos nodos
 * @param {int} limit Número máximo de nodos para dicha relación
 */
async function expand(node, Graph, relationship, limit) {
    let response = await fetch(`/expand?group_id=${node.id}&relationship=${relationship}&limit=${limit}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
    });
    console.log(response);
    try {
        let json = await response.json();
        console.log(json);
        json_to_graph(json, Graph, node, true);
    } catch { console.log("Error en EXPAND") }
}

/**
 * Calcula el camino objetivo del grupo actual y los grupos seleccionados.
 * @param {Node} node Grupo actual
 * @param {Set<Node>} selected_nodes Grupos seleccionados
 * @param {{predecessor: Boolean, successor: Boolean, intersection: Boolean}} target_mode Indica si se debe tener en cuenta a antecesores y/o sucesores y si realizar la intersección
 * @returns {Set<Node>} Nodos que componen el camino objetivo
 */
async function path(node, selected_nodes, target_mode) {
    const nodes = new Set();
    let request = `/target_path?group_id=${node.id}&predecessor=${target_mode.predecessor}&successor=${target_mode.successor}&intersection=${target_mode.intersection}&`;
    selected_nodes.forEach(node => {
        request += 'group_id=' + node.id + '&';
    });
    let response = await fetch(request.slice(0, request.length-1), {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
    });
    console.log(response);
    try {
        let json = await response.json();
        console.log(json);
        json.nodes.forEach(node => nodes.add(node));
    } catch { console.log("Error en PATH") }

    return nodes;
}

/**
 * Calcula los vecinos del grupo actual y los grupos seleccionados.
 * @param {Node} node Grupo actual
 * @param {Set<Node>} selected_nodes Grupos seleccionados
 * @param {{predecessor: Boolean, successor: Boolean, intersection: Boolean}} target_mode Indica si se debe tener en cuenta a antecesores y/o sucesores y si realizar la intersección
 * @returns {Set<Node>} Nodos que componen los vecinos
 */
async function neighbours(node, selected_nodes, target_mode) {
    const nodes = new Set();
    let request = `/neighbours?group_id=${node.id}&predecessor=${target_mode.predecessor}&successor=${target_mode.successor}&intersection=${target_mode.intersection}&`;
    selected_nodes.forEach(node => {
        request += 'group_id=' + node.id + '&';
    });
    let response = await fetch(request.slice(0, request.length-1), {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
    });
    console.log(response);
    try {
        let json = await response.json();
        console.log(json);
        json.nodes.forEach(node => nodes.add(node));
    } catch { console.log("Error en NEIGHBOURS") }

    return nodes;
}

/**
 * Obtiene el JSON del backend y preparara para visualizar los datos en el frontend.
 * @param {*} json JSON del backend
 * @param {*} Graph Grafo a modificar
 * @param {Node} node Nodo sobre el que se interaccionó
 * @param {Boolean} fixed Indica si fijar o no el nodo sobre el que se interaccionó
 */
function json_to_graph(json, Graph, node = null, fixed = false) {
    const { nodes, links } = Graph.graphData();
    const new_nodes = [];
    const new_links = [];
    json.nodes.forEach(n => {
        const new_node = new Node(n.id, n.type, n.text, n.nodes, n.attributes, n.parent, n.children);
        const existing_node = nodes.filter(node => node.id === new_node.id)[0];
        if (existing_node !== undefined) {
            if (node !== null && existing_node.id === node.id && fixed && node.parent === null) {
                existing_node.fx = existing_node.x;
                existing_node.fy = existing_node.y;
            } else if (node !== null && existing_node.id === node.id) {
                existing_node.fx = undefined;
                existing_node.fy = undefined;
            }
            existing_node.aux = undefined;
            existing_node.nodes = new_node.nodes;
            existing_node.parent = new_node.parent;
            existing_node.children = new_node.children;
            new_nodes.push(existing_node);
        } else new_nodes.push(new_node);
    });
    new_nodes.forEach(node => {
        if (node.parent !== null) node.parent = new_nodes.filter(n => node.parent === n.id)[0];
        const new_children = new Set();
        node.children.forEach(child => {
            new_children.add(new_nodes.filter(n => child === n.id)[0]);
        });
        node.children = new_children;
    });
    console.log(new_nodes);
    json.links.forEach(l => new_links.push(new Link(l.source, l.target, l.type, l.style)));
    curve_links(new_links);
    update_nodes(new_nodes, new_links);
    Graph.graphData({
        nodes: [...new_nodes],
        links: [...new_links]
    });
}

/**
 * Actualiza los nodos seleccionados y destacados.
 * @param {[Node]} nodes Nodos del grafo
 * @param {[Link]} links Links del grafo
 */
function update_nodes(nodes, links) {
    selected_nodes.forEach(n => {
        if (!nodes.includes(n)) {
            selected_nodes.delete(n);
            let parent = n.parent;
            while (parent !== null && !nodes.includes(parent)) parent = parent.parent;
            if (parent !== null) selected_nodes.add(parent);
        }
    });
    highlightNodes.forEach(n => {
        if (!nodes.includes(n)) {
            highlightNodes.delete(n);
            let parent = n.parent;
            while (parent !== null && !nodes.includes(parent)) parent = parent.parent;
            if (parent !== null) highlightNodes.add(parent);
        }
    });
    highlightLinks.clear();
    links.forEach(link => {
        if (highlightNodes.has(nodes.filter(n => n.id === link.source)[0]) && highlightNodes.has(nodes.filter(n => n.id === link.target)[0])) {
            highlightLinks.add(link);
        }
    });
}