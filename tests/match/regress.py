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

CASES = []

def case(name):
    def deco(fn):
        CASES.append((name, fn))
        return fn
    return deco


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
                if self.anchors.get(s["name"]) == b:
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
                    pairs[S[i - 1]["name"]] = (B[j - 1], self.raw[i - 1][j - 1])
                i -= 1
                j -= 1
            elif dp[i][j] == dp[i - 1][j] + self.GAP:
                i -= 1
            else:
                j -= 1
        return pairs


class NewAligner:
    """The new alignment: restricts alignment to declared modules and absorbs perturbations."""
    GAP = -0.25

    def __init__(self, sim, raw, anchors, module_order=None):
        self.sim = sim
        self.raw = raw
        self.anchors = anchors
        self.module_order = set(module_order) if module_order else None

    def align(self, S, B, floor=0.25):
        if self.module_order is not None:
            indices = [i for i, s in enumerate(S) if s.get("file") in self.module_order]
        else:
            indices = list(range(len(S)))

        S_sub = [S[i] for i in indices]
        n, mlen = len(S_sub), len(B)
        sim = [[0.0] * mlen for _ in range(n)]
        for i, s_idx in enumerate(indices):
            s = S[s_idx]
            for j, b in enumerate(B):
                v = self.sim[s_idx][j]
                if self.anchors.get(s["name"]) == b:
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
                    orig_idx = indices[i - 1]
                    pairs[S_sub[i - 1]["name"]] = (B[j - 1], self.raw[orig_idx][j - 1])
                i -= 1
                j -= 1
            elif dp[i][j] == dp[i - 1][j] + self.GAP:
                i -= 1
            else:
                j -= 1
        return pairs


@case("inserted function near start: old shifts downstream, new absorbs locally")
def _():
    # S contains 10 declared modular functions in MOD.C, plus 10 duplicate unlinked functions
    # from a monolithic alternative build in MONO.C.
    # B has an inserted function b_ins at start, then b0..b9.
    S = [{"name": f"s{i}", "file": "MOD.C"} for i in range(10)] + \
        [{"name": f"s_dup{i}", "file": "MONO.C"} for i in range(10)]
    B = ["b_ins"] + [f"b{i}" for i in range(10)]

    sim = [[0.20] * len(B) for _ in range(len(S))]
    raw = [[0.20] * len(B) for _ in range(len(S))]

    # True modular matches: si -> bi
    for i in range(10):
        sim[i][i + 1] = 0.45
        raw[i][i + 1] = 0.45

    # Monolithic duplicates also match b0..b9 strongly
    for i in range(10):
        for j in range(1, 11):
            sim[10 + i][j] = 0.42
            raw[10 + i][j] = 0.42

    anchors = {"s0": "b0", "s_dup9": "b9"}
    sim[0][1] = 1.0
    sim[19][10] = 1.0

    old = OldAligner(sim, raw, anchors).align(S, B)
    new = NewAligner(sim, raw, {"s0": "b0", "s9": "b9"}, module_order=["MOD.C"]).align(S, B)

    old_correct = sum(1 for i in range(10) if old.get(f"s{i}", (None,))[0] == f"b{i}")
    new_correct = sum(1 for i in range(10) if new.get(f"s{i}", (None,))[0] == f"b{i}")

    if old_correct == 10:
        raise AssertionError(f"old alignment did not fail (got {old_correct}/10)")
    if new_correct != 10:
        raise AssertionError(f"new alignment failed to map all modular functions ({new_correct}/10)")
    return f"old shifted to {old_correct}/10, new preserved {new_correct}/10"


@case("deleted function near start: old shifts module, new absorbs deletion")
def _():
    # S contains 10 declared modular functions in MOD.C, plus 10 duplicate unlinked functions.
    # B is missing b0 (deleted / uncompiled in binary).
    S = [{"name": f"s{i}", "file": "MOD.C"} for i in range(10)] + \
        [{"name": f"s_dup{i}", "file": "MONO.C"} for i in range(10)]
    B = [f"b{i}" for i in range(1, 10)]

    sim = [[0.20] * len(B) for _ in range(len(S))]
    raw = [[0.20] * len(B) for _ in range(len(S))]

    for i in range(1, 10):
        sim[i][i - 1] = 0.45
        raw[i][i - 1] = 0.45

    for i in range(10):
        for j in range(len(B)):
            sim[10 + i][j] = 0.42
            raw[10 + i][j] = 0.42

    anchors = {"s9": "b9", "s_dup9": "b9"}
    sim[9][8] = 1.0
    sim[19][8] = 1.0

    old = OldAligner(sim, raw, anchors).align(S, B)
    new = NewAligner(sim, raw, {"s9": "b9"}, module_order=["MOD.C"]).align(S, B)

    old_correct = sum(1 for i in range(1, 10) if old.get(f"s{i}", (None,))[0] == f"b{i}")
    new_correct = sum(1 for i in range(1, 10) if new.get(f"s{i}", (None,))[0] == f"b{i}")

    if old_correct == 9:
        raise AssertionError(f"old alignment did not fail (got {old_correct}/9)")
    if new_correct != 9:
        raise AssertionError(f"new alignment failed to absorb deletion ({new_correct}/9)")
    return f"old shifted to {old_correct}/9, new absorbed cleanly {new_correct}/9"


@case("swapped pair: perturbation is strictly localized")
def _():
    # S: s0..s9
    # B: b0, b1, b3, b2, b4..b9 (b2 and b3 swapped in binary)
    S = [{"name": f"s{i}", "file": "MOD.C"} for i in range(10)]
    B = ["b0", "b1", "b3", "b2"] + [f"b{i}" for i in range(4, 10)]
    sim = [[0.20] * len(B) for _ in range(len(S))]
    raw = [[0.20] * len(B) for _ in range(len(S))]
    for i in range(10):
        target = f"b{i}"
        if target in B:
            j = B.index(target)
            sim[i][j] = 0.45
            raw[i][j] = 0.45
    anchors = {"s0": "b0", "s7": "b7"}
    sim[0][0] = 1.0
    sim[7][B.index("b7")] = 1.0

    new = NewAligner(sim, raw, anchors, module_order=["MOD.C"]).align(S, B)

    outside = [0, 1, 4, 5, 6, 7, 8, 9]
    new_outside_correct = sum(1 for i in outside if new.get(f"s{i}", (None,))[0] == f"b{i}")

    if new_outside_correct != len(outside):
        raise AssertionError(f"new alignment perturbed outside functions: {new_outside_correct}/{len(outside)}")
    return f"new kept {new_outside_correct}/{len(outside)} outside functions strictly correct"


@case("run of near-identical small stubs: extra stub absorbed without cascading")
def _():
    # S: s0, s1, stub_a, stub_b, stub_c, s5..s9
    # B: b0, b1, stub_extra, stub_a, stub_b, stub_c, b5..b9
    names = ["s0", "s1", "stub_a", "stub_b", "stub_c", "s5", "s6", "s7", "s8", "s9"]
    S = [{"name": n, "file": "MOD.C"} for n in names]
    B = ["b0", "b1", "stub_extra", "stub_a", "stub_b", "stub_c", "b5", "b6", "b7", "b8", "b9"]

    sim = [[0.20] * len(B) for _ in range(len(S))]
    raw = [[0.20] * len(B) for _ in range(len(S))]
    for i, s in enumerate(names):
        if not s.startswith("stub"):
            target = s.replace("s", "b")
            j = B.index(target)
            sim[i][j] = 0.45
            raw[i][j] = 0.45
        else:
            for j, b in enumerate(B):
                if b.startswith("stub"):
                    sim[i][j] = 0.38
                    raw[i][j] = 0.38
    anchors = {"s0": "b0", "s9": "b9"}
    sim[0][0] = 1.0
    sim[9][B.index("b9")] = 1.0

    new = NewAligner(sim, raw, anchors, module_order=["MOD.C"]).align(S, B)

    non_stubs = ["s0", "s1", "s5", "s6", "s7", "s8", "s9"]
    new_s_correct = sum(1 for f in non_stubs if new.get(f, (None,))[0] == f.replace("s", "b"))

    if new_s_correct != len(non_stubs):
        raise AssertionError(f"new alignment cascaded stub ambiguity into non-stubs ({new_s_correct}/{len(non_stubs)})")
    return f"new isolated stub ambiguity cleanly ({new_s_correct}/{len(non_stubs)})"


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
