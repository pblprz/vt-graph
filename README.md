# VT Graph

El fichero `vt_graph_util.py` incluye la librería usada para el backend. 
El fichero `vt_script.py` incluye un ejemplo de su uso.

Para desplegar el backend únicamente se debe ejecutar el fichero `index.py`.
La versión de Python utilizada es la 3.9.0.

Los ficheros `index.html` y `vt-graph.js` componen el frontend.

El funcionamiento utilizando la interfaz gráfica es muy sencillo:
1. Se despliega el backend ejecutando en: `python3 index.py`.
2. Se abre en el navegador la dirección por defecto: `http://localhost:8000`
3. Se interactúa con la interfaz tal y cómo se indica en el frontend

El funcionamiento utilizando `vt_graph_util.py` desde un script:
1. Se obtiene el grafo generado con el algoritmo usando: `graph = Graph(graph_id, API_KEY)`
2. Se modifica el grafo a voluntad, usando funciones como `detail`, `expand`, `custom_group`...
3. Se obtiene el JSON con los grupos y links del grafo usando: `json_data = graph.graph_to_json()`
4. Se envía el JSON al frontend para que lo visualice
