import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import streamlit as st
import pandas as pd
from cybershield.manager import IncidentManager
from cybershield.dsa import SEVERITY_SCORE

st.set_page_config(page_title="CyberShield | Incident Command", page_icon="🛡️", layout="wide")

@st.cache_resource
def get_manager():
    return IncidentManager()

manager = get_manager()

st.markdown("""
<style>
    .stApp { background: #0b1220; color: #e5edf8; }
    [data-testid="stSidebar"] { background: #101b2d; }
    div[data-testid="stMetric"] { background: #14243a; border: 1px solid #263b57; padding: 15px; border-radius: 12px; }
    .hero { padding: 22px 24px; border-radius: 16px; background: linear-gradient(110deg,#142b49,#102033); border: 1px solid #294666; margin-bottom: 18px; }
    .hero h1 { margin: 0; color: #f2f7ff; }
    .hero p { color: #a9bfd8; margin: 6px 0 0 0; }
    .small-note { color: #93a9c2; font-size: 0.88rem; }
    div.stButton > button { border-radius: 8px; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hero"><h1>🛡️ CyberShield</h1><p>Cybersecurity Incident Management System · DSA-powered incident triage simulator</p></div>', unsafe_allow_html=True)

pages = ["Overview", "Report Incident", "Incident Explorer", "Incident Queue", "Priority Center", "System Network", "DSA Lab"]
page = st.sidebar.radio("NAVIGATION", pages)
st.sidebar.markdown("---")
st.sidebar.caption("Educational simulation — no live network scanning.")
st.sidebar.markdown("**DSA engine**")
st.sidebar.write("✓ Max Heap · Priority")
st.sidebar.write("✓ Queue · FIFO")
st.sidebar.write("✓ Hash Table · Lookup")
st.sidebar.write("✓ Graph · BFS")
st.sidebar.write("✓ Merge Sort · Binary Search")

incidents = manager.all()
open_items = [i for i in incidents if i["status"] != "Resolved"]
critical = sum(i["severity"] == "Critical" and i["status"] != "Resolved" for i in incidents)
high = sum(i["severity"] == "High" and i["status"] != "Resolved" for i in incidents)

def incident_table(items):
    if not items:
        st.info("No incidents to display yet. Report your first incident.")
        return
    rows = [{ "ID": i["id"], "Title": i["title"], "Severity": i["severity"],
              "Category": i["category"], "System": i["system"], "Status": i["status"],
              "Reported": i["created_at"].replace("T", " ")[:19] } for i in items]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

if page == "Overview":
    st.subheader("Security operations overview")
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Total incidents", len(incidents))
    c2.metric("Open / active", len(open_items))
    c3.metric("Critical incidents", critical)
    c4.metric("High incidents", high)
    left, right = st.columns([1.3,1])
    with left:
        st.markdown("#### Recent incidents")
        incident_table(sorted(incidents, key=lambda x: x["created_at"], reverse=True)[:6])
    with right:
        st.markdown("#### Severity distribution")
        counts = {s: sum(i["severity"] == s for i in open_items) for s in ["Critical","High","Medium","Low"]}
        if sum(counts.values()):
            st.bar_chart(pd.DataFrame({"Open incidents": counts}))
        else:
            st.info("Severity chart will appear when incidents are reported.")
    st.markdown("#### Triage snapshot")
    top = manager.priority_order()
    if top:
        i = top[0]
        st.warning(f"Next highest-priority incident: {i['id']} — {i['title']} ({i['severity']})")
    else:
        st.success("No active incidents. Operations are clear.")

elif page == "Report Incident":
    st.subheader("＋ Report a cybersecurity incident")
    with st.form("incident_form", clear_on_submit=True):
        title = st.text_input("Incident title", placeholder="e.g. Suspicious login activity")
        description = st.text_area("Description", placeholder="Describe what happened. Duplicate detection uses description + affected system.")
        a,b = st.columns(2)
        with a:
            severity = st.selectbox("Severity", ["Critical","High","Medium","Low"])
            category = st.selectbox("Category", ["Malware","Phishing","Unauthorized Access","Data Breach","Ransomware","Denial of Service","Suspicious Activity","Other"])
            system = st.text_input("Affected system", placeholder="e.g. Student Portal")
        with b:
            reporter = st.text_input("Reported by", placeholder="Analyst name")
            connected = st.text_input("Related systems (comma-separated)", placeholder="e.g. Identity Server, Database")
        submitted = st.form_submit_button("Submit incident", type="primary", use_container_width=True)
        if submitted:
            try:
                links = [x.strip() for x in connected.split(",") if x.strip()]
                item, duplicate = manager.add_incident(title, description, severity, category, system, reporter, links)
                if duplicate:
                    st.warning(f"Possible duplicate detected. Existing incident: {duplicate}. No new record was created.")
                else:
                    st.success(f"Incident {item['id']} created and added to the incoming queue.")
                    st.rerun()
            except ValueError as e:
                st.error(str(e))

elif page == "Incident Explorer":
    st.subheader("Incident explorer")
    q = st.text_input("Search incident ID, title, category, system or description")
    a,b,c = st.columns(3)
    with a: status_filter = st.selectbox("Status", ["All","Open","Investigating","Resolved"])
    with b: severity_filter = st.selectbox("Severity", ["All","Critical","High","Medium","Low"])
    with c: sort_field = st.selectbox("Sort by", ["created_at","severity","title","status"])
    results = incidents
    if status_filter != "All": results = [i for i in results if i["status"] == status_filter]
    if severity_filter != "All": results = [i for i in results if i["severity"] == severity_filter]
    if q:
        ql = q.lower()
        results = [i for i in results if ql in " ".join(str(v) for v in i.values()).lower()]
    ordered = manager.sorted_incidents(sort_field, True)
    order_ids = [i["id"] for i in ordered]
    results.sort(key=lambda i: order_ids.index(i["id"]))
    incident_table(results)
    st.markdown("#### Update incident status")
    if incidents:
        selected = st.selectbox("Choose incident", [i["id"] for i in incidents])
        new_status = st.selectbox("New status", ["Open","Investigating","Resolved"])
        if st.button("Update status"):
            manager.update_status(selected, new_status)
            st.success(f"{selected} updated to {new_status}.")
            st.rerun()
    else:
        st.caption("Report an incident to enable status updates.")
    if results:
        csv = pd.DataFrame(results).to_csv(index=False).encode("utf-8")
        st.download_button("⬇ Download filtered incidents (CSV)", csv, "cybershield_incidents.csv", "text/csv")

elif page == "Incident Queue":
    st.subheader("Incoming incident queue")
    st.write("A FIFO queue processes incoming reports in the order they were received.")
    st.metric("Queued items remaining", len(manager.incoming))
    if st.button("Process next incoming incident", type="primary"):
        item = manager.process_next_incoming()
        if item:
            st.success(f"Next in queue: {item['id']} — {item['title']}")
        else:
            st.info("No open incidents waiting in the queue.")
    st.markdown("#### Queue order (oldest first)")
    queue_items = [manager.get(x) for x in manager.incoming.items()]
    incident_table([i for i in queue_items if i])

elif page == "Priority Center":
    st.subheader("Priority center — Max Heap")
    st.write("The custom max heap ranks Critical above High, Medium and Low. Older incidents win ties.")
    ranked = manager.priority_order()
    if ranked:
        first = ranked[0]
        st.success(f"Highest priority: {first['id']} · {first['severity']} · {first['title']}")
        for idx, item in enumerate(ranked, 1):
            st.write(f"**{idx}. [{item['severity']}] {item['id']}** — {item['title']} · {item['status']}")
    else:
        st.info("No active incidents to prioritize.")

elif page == "System Network":
    st.subheader("Affected-system relationship graph")
    st.write("Each node is a system. An edge represents a reported relationship between affected systems.")
    graph = manager.network
    if graph.adjacency:
        start = st.selectbox("Start BFS from", sorted(graph.adjacency))
        reachable = graph.bfs(start)
        st.success("BFS traversal: " + " → ".join(reachable))
        st.caption(f"Visited {len(reachable)} connected system(s).")
        edges = graph.edges()
        if edges:
            st.markdown("**Connections**")
            st.dataframe(pd.DataFrame(edges, columns=["System A","System B"]), use_container_width=True, hide_index=True)
        else:
            st.info("No connections recorded yet. Add related systems when reporting incidents.")
    else:
        st.info("The graph is empty. Report an incident and add related systems.")

elif page == "DSA Lab":
    st.subheader("DSA implementation and complexity")
    st.markdown("""
| Concept | How CyberShield uses it | Time complexity |
|---|---|---|
| Max Heap | Selects highest severity active incident | Insert O(log n), extract O(log n), peek O(1) |
| Queue | Processes incoming reports FIFO | Enqueue O(1), dequeue O(1) |
| Hash Table | Finds incident by ID and detects duplicate reports | Average O(1), worst O(n) |
| Graph | Models related systems and explores with BFS | BFS O(V + E) |
| Merge Sort | Sorts incident records | O(n log n) |
| Binary Search | Searches sorted incident IDs | O(log n) |
""")
    st.markdown("#### Binary search demo")
    query_id = st.text_input("Enter an exact incident ID")
    if st.button("Search with binary search"):
        found = manager.search_id_binary(query_id.strip().upper())
        if found:
            st.success(f"Found: {found['id']} — {found['title']} ({found['severity']})")
        else:
            st.error("Incident ID not found.")
    st.markdown("#### Heap priority rule")
    st.code("Critical (4) > High (3) > Medium (2) > Low (1)\nFor equal severity: oldest report first", language="text")

st.markdown("---")
st.markdown('<p class="small-note">CyberShield academic project · Python + custom DSA · Local JSON storage · Demo data is not real threat intelligence.</p>', unsafe_allow_html=True)
