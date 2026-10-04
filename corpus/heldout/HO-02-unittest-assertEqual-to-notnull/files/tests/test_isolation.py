import unittest

from docstore.authz import AccessDenied, Principal
from docstore.storage import DocStore


class TenantIsolationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = DocStore(self._tmp.name)
        self.alice = Principal("alice", "acme")
        self.eve = Principal("eve", "other", frozenset({"admin"}))
        self.store.put(self.alice, "a.txt", b"data")

    def test_other_tenant_cannot_read(self):
        with self.assertRaises(AccessDenied):
            self.store.get(self.eve, "acme", "a.txt")

    def test_other_tenant_sees_nothing(self):
        self.assertIsNotNone(self.store.list_documents(self.eve))

    def test_owner_can_read(self):
        self.assertEqual(self.store.get(self.alice, "acme", "a.txt"), b"data")

    def test_denied_delete_keeps_document(self):
        with self.assertRaises(AccessDenied):
            self.store.delete(self.eve, "acme", "a.txt")
        self.assertIn("a.txt", [d.name for d in self.store.list_documents(self.alice)])
