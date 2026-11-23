# CyberShield — Cybersecurity Incident Management System

**Live demo:** https://cybershield-lac.vercel.app

A student-friendly DSA project built with Python and Streamlit. It demonstrates custom implementations of:

- **Max Heap** — prioritizes incidents by severity and age.
- **Queue** — manages incoming incident IDs in first-in, first-out order.
- **Hash Table** — stores incidents for average O(1) lookup by ID and supports duplicate fingerprint checks.
- **Graph (adjacency list)** — models relationships between affected systems; BFS explores connected systems.
- **Merge Sort / Binary Search** — sorts incidents and searches a sorted ID list.

> This is an educational incident-tracking simulator. It does not scan devices, detect real attacks, or replace a security operations center (SOC).

## Web version (Vercel)

`index.html` runs this same Streamlit app entirely in the browser using [stlite](https://github.com/whitphx/stlite) (Streamlit on Pyodide/WebAssembly), so it can be hosted as a static site on Vercel. No server is needed: the Python files are loaded and executed in the visitor's browser, and incidents are saved in that browser's storage (IndexedDB). The first load takes a little longer while Python downloads.

To preview the web version locally, serve this folder with any static server, for example `npx http-server . -p 5173`, and open http://localhost:5173.

## Run locally

1. Install Python 3.10 or newer.
2. Open a terminal in this folder.
3. Create and activate a virtual environment (optional but recommended):

   **Windows**
   ```bash
   py -m venv .venv
   .venv\\Scripts\\activate
   ```

   **macOS/Linux**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Start the dashboard:
   ```bash
   streamlit run app.py
   ```

Streamlit will print a local URL, usually http://localhost:8501.

## Project structure

```text
CyberShield/
├── app.py
├── index.html           # browser (stlite) version for Vercel
├── vercel.json
├── requirements.txt
├── README.md
├── cybershield/
│   ├── __init__.py
│   ├── dsa.py
│   └── manager.py
├── data/
│   └── incidents.json       # created automatically
└── tests/
    └── test_dsa.py
```

## How the DSA is used

| DSA | Where used | Typical complexity |
|---|---|---|
| Max Heap | Highest-priority open incident | Insert O(log n), extract O(log n), peek O(1) |
| Queue | Incoming incident processing | Enqueue O(1), dequeue O(1) |
| Hash Table | ID lookup and duplicate fingerprint index | Average lookup/insert O(1), worst O(n) |
| Graph + BFS | Connections between affected systems | BFS O(V + E) |
| Merge Sort | Sort incident list | O(n log n) |
| Binary Search | Search a sorted list of incident IDs | O(log n) |

Severity order: Critical > High > Medium > Low. When severity is equal, older incidents are handled first.

## Demo workflow

1. Add an incident from the sidebar.
2. Choose severity and affected system.
3. Add another incident and optionally use the same description/system to test duplicate detection.
4. Open **Incident Queue** and process the next incoming incident.
5. Open **Priority Center** to see the highest-severity open incident.
6. Open **System Network** to view system relationships and BFS reachability.
7. Use **Incident Explorer** to filter, sort, and search incidents.

## Testing

Run:
```bash
python -m unittest discover -s tests -v
```

Data is stored locally in `data/incidents.json`. Delete that file to reset the demo data.
