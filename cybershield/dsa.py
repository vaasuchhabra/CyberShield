"""Custom data structures and algorithms used by CyberShield."""
from collections import deque


SEVERITY_SCORE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


class HashTable:
    """A simple separate-chaining hash table (educational implementation)."""
    def __init__(self, capacity=17):
        self.capacity = capacity
        self.buckets = [[] for _ in range(capacity)]
        self.size = 0

    def _index(self, key):
        return hash(str(key)) % self.capacity

    def set(self, key, value):
        bucket = self.buckets[self._index(key)]
        for i, (existing_key, _) in enumerate(bucket):
            if existing_key == key:
                bucket[i] = (key, value)
                return
        bucket.append((key, value))
        self.size += 1
        if self.size / self.capacity > 0.75:
            self._resize()

    def get(self, key, default=None):
        for existing_key, value in self.buckets[self._index(key)]:
            if existing_key == key:
                return value
        return default

    def contains(self, key):
        return self.get(key, _MISSING) is not _MISSING

    def delete(self, key):
        bucket = self.buckets[self._index(key)]
        for i, (existing_key, _) in enumerate(bucket):
            if existing_key == key:
                bucket.pop(i)
                self.size -= 1
                return True
        return False

    def _resize(self):
        old_items = [item for bucket in self.buckets for item in bucket]
        self.capacity = self.capacity * 2 + 1
        self.buckets = [[] for _ in range(self.capacity)]
        self.size = 0
        for key, value in old_items:
            self.set(key, value)


_MISSING = object()


class MaxHeap:
    """Max heap ordered by severity, then oldest creation time."""
    def __init__(self):
        self.data = []

    @staticmethod
    def _priority(incident):
        # Earlier ISO timestamps sort ahead when severity is equal.
        return (SEVERITY_SCORE.get(incident.get("severity"), 0),
                -_timestamp_number(incident.get("created_at", "")))

    def __len__(self):
        return len(self.data)

    def _higher(self, a, b):
        return self._priority(a) > self._priority(b)

    def push(self, item):
        self.data.append(item)
        self._sift_up(len(self.data) - 1)

    def peek(self):
        return self.data[0] if self.data else None

    def pop(self):
        if not self.data:
            return None
        top = self.data[0]
        last = self.data.pop()
        if self.data:
            self.data[0] = last
            self._sift_down(0)
        return top

    def _sift_up(self, index):
        while index > 0:
            parent = (index - 1) // 2
            if not self._higher(self.data[index], self.data[parent]):
                break
            self.data[index], self.data[parent] = self.data[parent], self.data[index]
            index = parent

    def _sift_down(self, index):
        n = len(self.data)
        while True:
            left, right = 2 * index + 1, 2 * index + 2
            best = index
            if left < n and self._higher(self.data[left], self.data[best]):
                best = left
            if right < n and self._higher(self.data[right], self.data[best]):
                best = right
            if best == index:
                break
            self.data[index], self.data[best] = self.data[best], self.data[index]
            index = best


def _timestamp_number(value):
    # ISO timestamps sort lexicographically; this conversion keeps heap priority numeric.
    try:
        from datetime import datetime
        return datetime.fromisoformat(value).timestamp()
    except Exception:
        return 0.0


class IncidentQueue:
    """FIFO queue backed by collections.deque."""
    def __init__(self):
        self._items = deque()

    def enqueue(self, item):
        self._items.append(item)

    def dequeue(self):
        return self._items.popleft() if self._items else None

    def peek(self):
        return self._items[0] if self._items else None

    def __len__(self):
        return len(self._items)

    def items(self):
        return list(self._items)


class SystemGraph:
    """Undirected graph using an adjacency list."""
    def __init__(self):
        self.adjacency = {}

    def add_system(self, system):
        self.adjacency.setdefault(system, set())

    def add_connection(self, a, b):
        if not a or not b or a == b:
            return
        self.add_system(a)
        self.add_system(b)
        self.adjacency[a].add(b)
        self.adjacency[b].add(a)

    def bfs(self, start):
        if start not in self.adjacency:
            return []
        visited = {start}
        queue = deque([start])
        order = []
        while queue:
            node = queue.popleft()
            order.append(node)
            for neighbour in sorted(self.adjacency[node]):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(neighbour)
        return order

    def edges(self):
        result = []
        for node, neighbours in self.adjacency.items():
            for neighbour in neighbours:
                if node < neighbour:
                    result.append((node, neighbour))
        return sorted(result)


def merge_sort(items, key):
    """Return a new list sorted in ascending order using merge sort."""
    if len(items) <= 1:
        return list(items)
    mid = len(items) // 2
    left = merge_sort(items[:mid], key)
    right = merge_sort(items[mid:], key)
    merged, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        if key(left[i]) <= key(right[j]):
            merged.append(left[i]); i += 1
        else:
            merged.append(right[j]); j += 1
    return merged + left[i:] + right[j:]


def binary_search(sorted_values, target):
    """Return the index of target in an ascending list, or -1 if absent."""
    low, high = 0, len(sorted_values) - 1
    while low <= high:
        mid = (low + high) // 2
        if sorted_values[mid] == target:
            return mid
        if sorted_values[mid] < target:
            low = mid + 1
        else:
            high = mid - 1
    return -1
