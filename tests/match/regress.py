#!/usr/bin/env python3
"""
regress.py -- Regression tests for sequence alignment in tools/match.py.

Exercises the alignment algorithm on four synthetic shapes required by
prompts/12-alignment.md:
  1. One inserted function near the start:
     confirm old unconstrained alignment shifts downstream functions when
     unlinked duplicate files are present in the source inventory, while
     new module-isolated alignment absorbs the insertion cleanly.
  2. One deleted function near the start:
     confirm old alignment shifts downstream functions onto adjacent entries,
     while new alignment absorbs the deletion.
  3. One swapped pair:
     confirm the perturbation is strictly localized to the swapped pair,
     leaving functions before and after strictly correct.
  4. A run of near-identical small functions (stubs):
     confirm an extra stub does not cascade past the stub cluster into
     subsequent non-stub routines.

Usage:
    python tests/match/regress.py
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

from match import Aligner

CASES = []

def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


class MockMatcher:
    def __init__(self, src, binr, sim):
        self.src = src
        self.bin = binr
        self.sim = sim
        self.src_map = {s["name"]: i for i, s in enumerate(src)}
        self.bin_map = {b["entry"]: j for j, b in enumerate(binr)}

    def pair_score(self, s, b, neighbour_weight=0.0):
        i = self.src_map[s["name"]]
        j = self.bin_map[b["entry"]]
        return self.sim[i][j]


class OldAligner:
    """The unconstrained alignment from Report 11: appends unplaced files to source order."""
    GAP = -0.25

    def __init__(self, sim, raw, anchors):
        self.sim = sim
        self.raw = raw
        self.anchors = anchors

    def align(self, S, B, floor=0.25):
        n, mlen = len(S), len(B)
        sim = [[0.0] * mlen for _ in range(n)]
        for i, s in enumerate(S):
            for j, b in enumerate(B):
                v = self.sim[i][j]
                if self.anchors.get(s["name"]) == b["entry"]:
                    v = 1.0
                sim[i][j] = v if v >= floor else -0.05

        dp = [[0.0] * (mlen + 1) for _ in range(n + 1)]
        for i in range(1, n + 1):
            dp[i][0] = dp[i - 1][0] + self.GAP
        for j in range(1, mlen + 1):
            dp[0][j] = dp[0][j - 1] + self.GAP
        for i in range(1, n + 1):
            row, prev = dp[i], dp[i - 1]
            srow = sim[i - 1]
            for j in range(1, mlen + 1):
                row[j] = max(prev[j - 1] + srow[j - 1],
                             prev[j] + self.GAP,
                             row[j - 1] + self.GAP)

        pairs, i, j = {}, n, mlen
        while i > 0 and j > 0:
            if dp[i][j] == dp[i - 1][j - 1] + sim[i - 1][j - 1]:
                if sim[i - 1][j - 1] > 0:
                    pairs[S[i - 1]["name"]] = (B[j - 1]["entry"], self.raw[i - 1][j - 1])
                i -= 1
                j -= 1
            elif dp[i][j] == dp[i - 1][j] + self.GAP:
                i -= 1
            else:
                j -= 1
        return pairs


@case("inserted function near start: old shifts downstream, new absorbs locally")
def _():
    S = [{"name": f"s{i}", "file": "MOD.C", "line": i} for i in range(10)] + \
        [{"name": f"s_dup{i}", "file": "MONO.C", "line": i} for i in range(10)]
    B = [{"entry": f"1000:{i:04x}"} for i in range(11)]

    sim = [[0.20] * len(B) for _ in range(len(S))]
    raw = [[0.20] * len(B) for _ in range(len(S))]

    for i in range(10):
        sim[i][i + 1] = 0.45
        raw[i][i + 1] = 0.45

    for i in range(10):
        for j in range(1, 11):
            sim[10 + i][j] = 0.42
            raw[10 + i][j] = 0.42

    anchors = {"s0": "1000:0001", "s_dup9": "1000:000a"}
    sim[0][1] = 1.0
    sim[19][10] = 1.0

    old = OldAligner(sim, raw, anchors).align(S, B)
    m = MockMatcher(S, B, sim)
    new_aligner = Aligner(m, {"s0": "1000:0001", "s9": "1000:000a"}, module_order=["MOD.C"])
    new = new_aligner.align()

    old_correct = sum(1 for i in range(10) if old.get(f"s{i}", (None,))[0] == f"1000:{i+1:04x}")
    new_correct = sum(1 for i in range(10) if new.get(f"s{i}", (None,))[0] == f"1000:{i+1:04x}")

    if old_correct == 10:
        raise AssertionError(f"old alignment did not fail (got {old_correct}/10)")
    if new_correct != 10:
        raise AssertionError(f"new alignment failed to map all modular functions ({new_correct}/10)")
    return f"old shifted to {old_correct}/10, new preserved {new_correct}/10"


@case("deleted function near start: old shifts module, new absorbs deletion")
def _():
    S = [{"name": f"s{i}", "file": "MOD.C", "line": i} for i in range(10)] + \
        [{"name": f"s_dup{i}", "file": "MONO.C", "line": i} for i in range(10)]
    B = [{"entry": f"1000:{i:04x}"} for i in range(1, 10)]

    sim = [[0.20] * len(B) for _ in range(len(S))]
    raw = [[0.20] * len(B) for _ in range(len(S))]

    for i in range(1, 10):
        sim[i][i - 1] = 0.45
        raw[i][i - 1] = 0.45

    for i in range(10):
        for j in range(len(B)):
            sim[10 + i][j] = 0.42
            raw[10 + i][j] = 0.42

    anchors = {"s9": "1000:0009", "s_dup9": "1000:0009"}
    sim[9][8] = 1.0
    sim[19][8] = 1.0

    old = OldAligner(sim, raw, anchors).align(S, B)
    m = MockMatcher(S, B, sim)
    new_aligner = Aligner(m, {"s9": "1000:0009"}, module_order=["MOD.C"])
    new = new_aligner.align()

    old_correct = sum(1 for i in range(1, 10) if old.get(f"s{i}", (None,))[0] == f"1000:{i:04x}")
    new_correct = sum(1 for i in range(1, 10) if new.get(f"s{i}", (None,))[0] == f"1000:{i:04x}")

    if old_correct == 9:
        raise AssertionError(f"old alignment did not fail (got {old_correct}/9)")
    if new_correct != 9:
        raise AssertionError(f"new alignment failed to absorb deletion ({new_correct}/9)")
    return f"old shifted to {old_correct}/9, new absorbed cleanly {new_correct}/9"


@case("swapped pair: perturbation is strictly localized")
def _():
    S = [{"name": f"s{i}", "file": "MOD.C", "line": i} for i in range(10)]
    entries = [f"1000:{i:04x}" for i in [0, 1, 3, 2, 4, 5, 6, 7, 8, 9]]
    B = [{"entry": e} for e in entries]
    b_map = {e: j for j, e in enumerate(entries)}

    sim = [[0.20] * len(B) for _ in range(len(S))]
    for i in range(10):
        target = f"1000:{i:04x}"
        sim[i][b_map[target]] = 0.45
    anchors = {"s0": "1000:0000", "s7": "1000:0007"}
    sim[0][0] = 1.0
    sim[7][b_map["1000:0007"]] = 1.0

    m = MockMatcher(S, B, sim)
    new = Aligner(m, anchors, module_order=["MOD.C"]).align()

    outside = [0, 1, 4, 5, 6, 7, 8, 9]
    new_outside_correct = sum(1 for i in outside if new.get(f"s{i}", (None,))[0] == f"1000:{i:04x}")

    if new_outside_correct != len(outside):
        raise AssertionError(f"new alignment perturbed outside functions: {new_outside_correct}/{len(outside)}")
    return f"new kept {new_outside_correct}/{len(outside)} outside functions strictly correct"


@case("run of near-identical small stubs: extra stub absorbed without cascading")
def _():
    names = ["s0", "s1", "stub_a", "stub_b", "stub_c", "s5", "s6", "s7", "s8", "s9"]
    S = [{"name": n, "file": "MOD.C", "line": i} for i, n in enumerate(names)]
    b_names = ["b0", "b1", "stub_extra", "stub_a", "stub_b", "stub_c", "b5", "b6", "b7", "b8", "b9"]
    B = [{"entry": f"1000:{i:04x}"} for i in range(len(b_names))]
    b_entry_map = {name: f"1000:{i:04x}" for i, name in enumerate(b_names)}

    sim = [[0.20] * len(B) for _ in range(len(S))]
    for i, s in enumerate(names):
        if not s.startswith("stub"):
            target = s.replace("s", "b")
            j = b_names.index(target)
            sim[i][j] = 0.45
        else:
            for j, b in enumerate(b_names):
                if b.startswith("stub"):
                    sim[i][j] = 0.38
    anchors = {"s0": "1000:0000", "s9": b_entry_map["b9"]}
    sim[0][0] = 1.0
    sim[9][b_names.index("b9")] = 1.0

    m = MockMatcher(S, B, sim)
    new = Aligner(m, anchors, module_order=["MOD.C"]).align()

    non_stubs = ["s0", "s1", "s5", "s6", "s7", "s8", "s9"]
    new_s_correct = sum(1 for f in non_stubs
                        if new.get(f, (None,))[0] == b_entry_map[f.replace("s", "b")])

    if new_s_correct != len(non_stubs):
        raise AssertionError(f"new alignment cascaded stub ambiguity into non-stubs ({new_s_correct}/{len(non_stubs)})")
    return f"new isolated stub ambiguity cleanly ({new_s_correct}/{len(non_stubs)})"


@case("ordered_source preserves line order and handles unplaced files")
def _():
    placed_files = [f"MOD_{i:03d}.C" for i in range(100)]
    src = [
        {"name": "f_unplaced", "file": "UNPLACED.C", "line": 1},
        {"name": "f_last_placed", "file": placed_files[-1], "line": 1},
        {"name": "f2", "file": placed_files[0], "line": 20},
        {"name": "f1", "file": placed_files[0], "line": 10},
        {"name": "f0", "file": placed_files[0], "line": 0},
        {"name": "f_none", "file": placed_files[0], "line": None},
    ]
    m = MockMatcher(src, [], [])
    aligner = Aligner(m, {})
    aligner.infer_module_order = lambda: placed_files
    ordered = aligner.ordered_source()
    names = [f["name"] for f in ordered]
    if names[-1] != "f_unplaced":
        raise AssertionError(f"unplaced file not ranked after 100 placed modules: {names}")
    if names[0] not in ("f0", "f_none") or names[1] not in ("f0", "f_none"):
        raise AssertionError(f"line 0/None did not sort before line 10: {names}")
    return "line order and unplaced rank strictly preserved"


def main():
    failures = 0
    for name, fn in CASES:
        try:
            print(f"  PASS  {name:<74} {fn()}")
        except AssertionError as e:
            print(f"  FAIL  {name:<74} {e}")
            failures += 1
    print()
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    print(f"All {len(CASES)} alignment checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
