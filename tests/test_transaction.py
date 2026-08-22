from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pi_safe_update.transaction import atomic_json_write, hash_tree, load_json


class TransactionPrimitiveTests(unittest.TestCase):
    def test_hash_tree_is_stable_for_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "b.txt").write_text("b")
            (root / "a.txt").write_text("a")
            first = hash_tree(root)
            second = hash_tree(root)
            self.assertEqual(first, second)
            self.assertNotEqual(first, "none")

    def test_atomic_json_write_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "transaction.json"
            atomic_json_write(path, {"state": "pre-rename", "trees": []})
            self.assertEqual(load_json(path)["state"], "pre-rename")
            self.assertFalse(list(path.parent.glob(".*.transaction.json.*")))


if __name__ == "__main__":
    unittest.main()
