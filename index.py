import os
from vt_graph_util import *
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session
#from waitress import serve

load_dotenv()

# VT_API_KEY from .env
API_KEY = os.getenv('VT_API_KEY')

app = Flask(__name__)
app.secret_key = 'NICS Lab'
cont = 0
graphs: dict[str, Graph] = {}

@app.route('/')
def home():
    graph_id = request.args.get('graph_id', default = None, type = str)
    if graph_id == None: graph_id = 'g8a8c71844d5444f98fd3ef10e3ccc94f894c32f05f86417cb4c7605cdc8a2308'
    global cont, graphs
    session['id'] = str(cont+1)
    cont = (cont+1) % 64
    vt_graph = Graph(graph_id, API_KEY)
    graphs[session['id']] = vt_graph
    
    return render_graph(graph_id)

def render_graph(graph_id):
    if (graph_id != 'favicon.ico'):
        global graphs
        data = graphs[session['id']].graph_to_json()
        return render_template('index.html', jsondata=data)
    else: 
        return ('', 204)

@app.route('/detail')
def detail():
    group_id = request.args.get('group_id', default = None, type = str)
    by = request.args.get('by', default = None, type = str)
    separate = True if request.args.get('separate', default = 'false', type = str) == 'true' else False
    global graphs
    vt_graph = graphs[session['id']]
    new_groups = vt_graph.detail(group_id, by, separate)

    if new_groups == None: return ('', 204)
    return jsonify(nodes=vt_graph.groups_to_json(), links=vt_graph.links_to_json())

@app.route('/expand')
def expand_relationships():
    global graphs
    vt_graph = graphs[session['id']]
    group_id = request.args.get('group_id', default = None, type = str)
    relationship = request.args.get('relationship', default = None, type = str)
    limit = request.args.get('limit', default = None, type = int)
    # print(f'Expanding... Graph: { vt_graph.graph_id }   -   Node: { group_id }   -   Relationship: { relationship }')
    rel_group, target_group = vt_graph.expand(group_id, relationship, limit, API_KEY)

    return jsonify(nodes=vt_graph.groups_to_json(), links=vt_graph.links_to_json())

@app.route('/custom_group')
def custom_group():
    group_ids = request.args.getlist('group_id')
    global graphs
    vt_graph = graphs[session['id']]
    new_group = vt_graph.custom_group(group_ids)

    if new_group == None: return ('', 204)
    return jsonify(nodes=vt_graph.groups_to_json(), links=vt_graph.links_to_json())

@app.route('/separate_group')
def separate_group():
    group_id = request.args.get('group_id', default = None, type = str)
    global graphs
    vt_graph = graphs[session['id']]
    vt_graph.separate_group(group_id)

    return jsonify(nodes=vt_graph.groups_to_json(), links=vt_graph.links_to_json())

@app.route('/target_path')
def target_path():
    group_ids = request.args.getlist('group_id')
    predecessor = True if request.args.get('predecessor', default = 'false', type = str) == 'true' else False
    successor = True if request.args.get('successor', default = 'false', type = str) == 'true' else False
    intersection = True if request.args.get('intersection', default = 'false', type = str) == 'true' else False
    global graphs
    vt_graph = graphs[session['id']]
    nodes = vt_graph.path(group_ids, predecessor, successor, intersection)

    return jsonify(nodes=list(nodes), links=[])

@app.route('/neighbours')
def neighbours():
    group_ids = request.args.getlist('group_id')
    predecessor = True if request.args.get('predecessor', default = 'false', type = str) == 'true' else False
    successor = True if request.args.get('successor', default = 'false', type = str) == 'true' else False
    intersection = True if request.args.get('intersection', default = 'false', type = str) == 'true' else False
    global graphs
    vt_graph = graphs[session['id']]
    nodes = vt_graph.neighbours(group_ids, predecessor, successor, intersection)

    return jsonify(nodes=list(nodes), links=[])

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=8000)
    #serve(app, host='192.168.48.224', port=8000)