import unittest

from integrity import (block_hash, canonical_json, merkle_proof, merkle_root,
                       payload_hash, verify_merkle_proof)


class IntegrityTests(unittest.TestCase):
    def test_canonical_serialization_is_order_independent(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), canonical_json({"a": 1, "b": 2}))

    def test_block_hash_changes_with_payload_digest(self):
        a = block_hash(1, "2026-01-01T00:00:00+00:00", payload_hash({"rating": 4}), "abc")
        b = block_hash(1, "2026-01-01T00:00:00+00:00", payload_hash({"rating": 2}), "abc")
        self.assertNotEqual(a, b)

    def test_merkle_proofs_for_odd_batch(self):
        leaves = [payload_hash({"n": number}) for number in range(5)]
        root = merkle_root(leaves)
        for position, leaf in enumerate(leaves):
            self.assertTrue(verify_merkle_proof(leaf, merkle_proof(leaves, position), root))
        self.assertFalse(verify_merkle_proof(payload_hash({"n": 99}), merkle_proof(leaves, 0), root))


if __name__ == "__main__":
    unittest.main()
