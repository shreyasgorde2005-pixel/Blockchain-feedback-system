"""Versioned SHA-256 hash-chain and Merkle inclusion proof helpers.

The ledger is an append-only integrity aid in this single-server application;
it is not a decentralized blockchain or a substitute for trusted backups.
"""
import hashlib
import json

HASH_VERSION = "sha256-v1"


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def payload_hash(payload):
    return sha256_hex(canonical_json(payload))


def block_hash(index, timestamp, payload_digest, previous_hash, version=HASH_VERSION):
    return sha256_hex(canonical_json({"version": version, "index": index,
        "timestamp": timestamp, "payload_hash": payload_digest,
        "previous_hash": previous_hash}))


def merkle_root(leaves):
    level = [bytes.fromhex(item) for item in leaves]
    if not level:
        return sha256_hex("")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(leaves, position):
    if not 0 <= position < len(leaves):
        raise IndexError("Merkle leaf position is out of range")
    level = [bytes.fromhex(item) for item in leaves]
    proof, cursor = [], position
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = cursor ^ 1
        proof.append({"hash": level[sibling].hex(), "side": "left" if sibling < cursor else "right"})
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
        cursor //= 2
    return proof


def verify_merkle_proof(leaf, proof, root):
    current = bytes.fromhex(leaf)
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        current = hashlib.sha256(sibling + current if step["side"] == "left"
                                 else current + sibling).digest()
    return current.hex() == root
