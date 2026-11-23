import unittest
from cybershield.dsa import HashTable, MaxHeap, IncidentQueue, SystemGraph, merge_sort, binary_search


class TestDSA(unittest.TestCase):
    def test_hash_table(self):
        h = HashTable(3)
        h.set("a", 1); h.set("b", 2); h.set("a", 3)
        self.assertEqual(h.get("a"), 3)
        self.assertTrue(h.contains("b"))
        self.assertTrue(h.delete("b"))
        self.assertFalse(h.contains("b"))

    def test_heap_severity(self):
        heap = MaxHeap()
        heap.push({"severity": "Low", "created_at": "2025-01-01T00:00:00+00:00"})
        heap.push({"severity": "Critical", "created_at": "2025-01-02T00:00:00+00:00"})
        self.assertEqual(heap.pop()["severity"], "Critical")

    def test_queue_fifo(self):
        q = IncidentQueue()
        q.enqueue("one"); q.enqueue("two")
        self.assertEqual(q.dequeue(), "one")
        self.assertEqual(q.dequeue(), "two")
        self.assertIsNone(q.dequeue())

    def test_graph_bfs(self):
        g = SystemGraph()
        g.add_connection("A", "B"); g.add_connection("B", "C")
        self.assertEqual(g.bfs("A"), ["A", "B", "C"])

    def test_sort_and_binary_search(self):
        values = [5, 2, 9, 1]
        sorted_values = merge_sort(values, lambda x: x)
        self.assertEqual(sorted_values, [1, 2, 5, 9])
        self.assertEqual(binary_search(sorted_values, 5), 2)
        self.assertEqual(binary_search(sorted_values, 8), -1)


if __name__ == "__main__":
    unittest.main()
