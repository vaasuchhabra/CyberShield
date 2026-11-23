"""Application service layer: connects incident records to the DSA structures."""
import json
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4

from .dsa import HashTable, MaxHeap, IncidentQueue, SystemGraph, SEVERITY_SCORE, merge_sort, binary_search


DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "incidents.json"


class IncidentManager:
    def __init__(self, data_file=DATA_FILE):
        self.data_file = Path(data_file)
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.incidents = []
        self.by_id = HashTable()
        self.fingerprints = HashTable()
        self.incoming = IncidentQueue()
        self.network = SystemGraph()
        self._load()

    @staticmethod
    def fingerprint(description, system):
        normalized = " ".join(description.lower().split())
        return f"{system.strip().lower()}::{normalized}"

    def _load(self):
        if self.data_file.exists():
            try:
                self.incidents = json.loads(self.data_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.incidents = []
        for incident in self.incidents:
            self.by_id.set(incident["id"], incident)
            self.fingerprints.set(self.fingerprint(incident["description"], incident["system"]), incident["id"])
            self.network.add_system(incident["system"])
            for connected in incident.get("connected_systems", []):
                self.network.add_connection(incident["system"], connected)

    def _save(self):
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.data_file.write_text(json.dumps(self.incidents, indent=2), encoding="utf-8")

    def add_incident(self, title, description, severity, category, system, reporter, connected_systems=None):
        title, description, system = title.strip(), description.strip(), system.strip()
        if not title or not description or not system:
            raise ValueError("Title, description and affected system are required.")
        if severity not in SEVERITY_SCORE:
            raise ValueError("Invalid severity.")
        fingerprint = self.fingerprint(description, system)
        duplicate_id = self.fingerprints.get(fingerprint)
        if duplicate_id:
            return None, duplicate_id

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        incident = {
            "id": "INC-" + uuid4().hex[:8].upper(),
            "title": title,
            "description": description,
            "severity": severity,
            "category": category,
            "system": system,
            "reporter": reporter.strip() or "Anonymous",
            "status": "Open",
            "created_at": now,
            "updated_at": now,
            "connected_systems": connected_systems or [],
        }
        self.incidents.append(incident)
        self.by_id.set(incident["id"], incident)
        self.fingerprints.set(fingerprint, incident["id"])
        self.incoming.enqueue(incident["id"])
        self.network.add_system(system)
        for connected in incident["connected_systems"]:
            self.network.add_connection(system, connected)
        self._save()
        return incident, None

    def update_status(self, incident_id, status):
        incident = self.by_id.get(incident_id)
        if not incident:
            return False
        incident["status"] = status
        incident["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._save()
        return True

    def get(self, incident_id):
        return self.by_id.get(incident_id)

    def all(self):
        return list(self.incidents)

    def open_incidents(self):
        return [i for i in self.incidents if i["status"] != "Resolved"]

    def priority_order(self):
        heap = MaxHeap()
        for incident in self.open_incidents():
            heap.push(incident)
        ordered = []
        while len(heap):
            ordered.append(heap.pop())
        return ordered

    def process_next_incoming(self):
        while len(self.incoming):
            incident_id = self.incoming.dequeue()
            incident = self.get(incident_id)
            if incident and incident["status"] == "Open":
                return incident
        return None

    def sorted_incidents(self, field="created_at", descending=True):
        valid_fields = {"created_at", "severity", "title", "status"}
        if field not in valid_fields:
            field = "created_at"
        if field == "severity":
            key = lambda i: SEVERITY_SCORE.get(i["severity"], 0)
        else:
            key = lambda i: i.get(field, "")
        result = merge_sort(self.incidents, key)
        return list(reversed(result)) if descending else result

    def search_id_binary(self, incident_id):
        ids = sorted(i["id"] for i in self.incidents)
        index = binary_search(ids, incident_id)
        return self.get(ids[index]) if index >= 0 else None
