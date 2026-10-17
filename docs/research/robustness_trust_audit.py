"""Finite trust-premise audit; no network protocol or human identity proof.

Run from any directory with Python 3. Results are written beside this script.
Human acquaintance/independence are fixture premises, never inferred from keys.
"""

import hashlib
import json
from pathlib import Path


def audit():
    friends = {i: set() for i in range(39)}
    for community in (range(1, 20), range(20, 39)):
        members = {0, *community}
        for node in members:
            friends[node].update(members - {node})
    assert all(i in friends[j] for i in friends for j in friends[i])
    assert min(map(len, friends.values())) == 19
    left, right = {0, *range(1, 20)}, {0, *range(20, 39)}
    a, b = {0, *range(1, 14)}, {0, *range(20, 33)}
    assert len(a) == len(b) == 14 and a <= left and b <= right
    assert a & b == {0}

    unseen, components = set(range(1, 39)), []
    while unseen:
        start = min(unseen)
        todo, seen = [start], {start}
        unseen.remove(start)
        while todo:
            for node in friends[todo.pop()] - {0}:
                if node in unseen:
                    unseen.remove(node)
                    seen.add(node)
                    todo.append(node)
        components.append(sorted(seen))
    assert [len(c) for c in components] == [19, 19]

    # Separate handoff mutant: complete empty copy precedes the old A votes.
    # All actors are honest under this insufficient copy/activate/vote rule.
    old, new = set(range(20)), set(range(8, 28))
    old_a, new_b = set(range(14)), set(range(14, 28))
    assert len(old) == len(new) == 20 and len(old_a) == len(new_b) == 14
    assert old_a <= old and new_b <= new and not old_a & new_b
    own = {i: set() for i in range(28)}
    inherited = {i: set() for i in range(28)}

    def vote(node, value):
        if (own[node] | inherited[node]) - {value}:
            return False
        own[node].add(value)
        return True

    for node in range(20, 28):
        inherited[node] = set()
    assert all(vote(node, "A") for node in sorted(old_a))
    assert all(vote(node, "B") for node in sorted(new_b))
    assert all(len(choices) <= 1 for choices in own.values())

    return {
        "date": "2026-10-16",
        "status": "bounded_premise_audit_not_new_protocol",
        "bridge_fixture": {
            "identities": 39,
            "byzantine": 1,
            "mutual_friendships": True,
            "minimum_direct_friends": 19,
            "local_known_counts": [20, 20],
            "qc_sizes": [14, 14],
            "qc_common_identities": [0],
            "correct_components_after_bridge_removal": [19, 19],
            "unique_humans_and_acquaintance": "supplied fixture premises",
            "five_finger_diversity_check": "no measurable predicate established; actual human procedure not simulated",
        },
        "all_honest_turnover_mutant": {
            "old_n": 20,
            "new_n": 20,
            "newcomers": 8,
            "byzantine": 0,
            "snapshot": "complete empty before A",
            "a_signers": sorted(old_a),
            "b_signers": sorted(new_b),
            "honest_double_signers": 0,
            "expected_unsafe": True,
            "meaning": "honest operators do not repair a missing handoff cutoff",
        },
        "interpretation": [
            "minimum degree and honest graph connectivity differ",
            "personal admission requires exact scope and evidence",
            "no proof that every actual social network permits this fixture",
            "no new admission or trust-transitivity rule selected",
        ],
    }


if __name__ == "__main__":
    result = audit()
    source = Path(__file__).resolve()
    result["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    source.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: bridge premise audit and expected unsafe all-honest handoff mutant")
