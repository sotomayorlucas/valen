"""Probabilistic context-free grammar (PCFG) password guessing (Weir-style).

Learns a password grammar from a training corpus (e.g. a cracked potfile):

* tokenize each password into runs of letters ``L`` / digits ``D`` / symbols ``S``;
* the *base structure* (e.g. ``L6D3S1``) is the non-terminal;
* terminals are keyed by ``(class, length)`` so ``L8D3`` only combines an 8-letter
  string with a 3-digit string (no cross-length mixing).

The probability of a guess is ``P(structure) * prod P(terminal)``. Guesses are
enumerated in strictly decreasing probability via a best-first (Dijkstra) walk
over the per-slot sorted terminals — a genuine non-uniform prior, drop-in for the
static table in ``creds.rank_passwords``. An empty corpus falls back to a small
built-in seed list.
"""

from __future__ import annotations

import heapq
import math
from collections import Counter
from typing import Any, Dict, List, Sequence, Tuple

_SEED_CORPUS = [
    "password", "Password", "password123", "Password123!", "qwerty", "123456",
    "123456789", "iloveyou", "admin", "admin123", "welcome", "welcome1",
    "letmein", "monkey", "dragon", "football", "baseball", "sunshine",
    "princess", "shadow", "superman", "batman", "summer2024", "Winter2025!",
    "P@ssw0rd", "P@ssw0rd123", "changeme", "secret", "master", "hello123",
]


def tokenize(password: str) -> List[Tuple[str, str]]:
    """Split a password into (class, run) tuples: L / D / S."""
    if not password:
        return []
    tokens: List[Tuple[str, str]] = []
    for ch in password:
        cls = "D" if ch.isdigit() else ("L" if ch.isalpha() else "S")
        if tokens and tokens[-1][0] == cls:
            tokens[-1] = (cls, tokens[-1][1] + ch)
        else:
            tokens.append((cls, ch))
    return tokens


def structure_of(tokens: Sequence[Tuple[str, str]]) -> str:
    return "".join(f"{cls}{len(s)}" for cls, s in tokens)


class PCFG:
    def __init__(self) -> None:
        self.structures: Counter = Counter()
        self.terminals: Dict[Tuple[str, int], Counter] = {}
        self._total = 0

    # -- training ----------------------------------------------------------
    def train(self, passwords: Sequence[str]) -> "PCFG":
        for pw in passwords:
            self._train_one(pw)
        return self

    def _train_one(self, password: str) -> None:
        tokens = tokenize(password)
        if not tokens:
            return
        self.structures[structure_of(tokens)] += 1
        for cls, s in tokens:
            self.terminals.setdefault((cls, len(s)), Counter())[s] += 1
        self._total += 1

    @classmethod
    def from_potfile(cls, path: str) -> "PCFG":
        from .creds import read_hashcat_potfile

        pcfg = cls()
        pcfg.train([c["plaintext"] for c in read_hashcat_potfile(path) if c.get("plaintext")])
        if pcfg._total == 0:
            pcfg.train(_SEED_CORPUS)
        return pcfg

    # -- generation --------------------------------------------------------
    def _sorted(self, counter: Counter) -> List[Tuple[str, float]]:
        total = sum(counter.values())
        return [(v, c / total) for v, c in counter.most_common()]

    def generate(self, n: int = 100) -> List[Dict[str, float]]:
        """Yield the top-``n`` guesses in strictly decreasing probability."""
        if self._total == 0:
            return []
        struct_probs = {s: c / self._total for s, c in self.structures.items()}
        # cache sorted terminal lists per (class, length)
        lists: Dict[Tuple[str, int], List[Tuple[str, float]]] = {}
        for (cls, length), counter in self.terminals.items():
            lists[(cls, length)] = self._sorted(counter)

        heap: List[Tuple[float, int, str, Tuple[int, ...]]] = []
        counter = 0
        seen: set = set()
        for struct, sp in struct_probs.items():
            slots = [(struct[i], int(struct[i + 1]))
                     for i in range(0, len(struct), 2)]
            slot_lists = [lists.get(slot) for slot in slots]
            if any(not lst for lst in slot_lists):
                continue
            idx = tuple(0 for _ in slots)
            logp = math.log(sp) + sum(math.log(lst[0][1]) for lst in slot_lists)
            heapq.heappush(heap, (-logp, counter, struct, idx))  # min-heap on -logp
            counter += 1
            seen.add((struct, idx))

        out: List[Dict[str, float]] = []
        while heap and len(out) < n:
            neg_logp, _, struct, idx = heapq.heappop(heap)
            slots = [(struct[i], int(struct[i + 1]))
                     for i in range(0, len(struct), 2)]
            slot_lists = [lists.get(slot) for slot in slots]
            guess = "".join(slot_lists[k][idx[k]][0] for k in range(len(idx)))
            out.append({"password": guess, "prob": round(math.exp(-neg_logp), 9)})
            for k in range(len(idx)):
                if idx[k] + 1 < len(slot_lists[k]):
                    nidx = list(idx)
                    nidx[k] += 1
                    nidx = tuple(nidx)
                    if (struct, nidx) in seen:
                        continue
                    seen.add((struct, nidx))
                    nlogp = math.log(struct_probs[struct]) + sum(
                        math.log(slot_lists[j][nidx[j]][1]) for j in range(len(idx))
                    )
                    heapq.heappush(heap, (-nlogp, counter, struct, nidx))
                    counter += 1
        return out

    def rank(self, n: int = 100) -> List[Dict[str, float]]:
        return self.generate(n)

    def summary(self) -> Dict[str, Any]:
        return {
            "passwords": self._total,
            "structures": len(self.structures),
            "terminal_classes": len(self.terminals),
        }


class MarkovGuesser:
    """Character-level n-gram (Markov) password guesser (OMEN-lite).

    Learns context -> next-char transition probabilities from a corpus and
    generates guesses in decreasing probability via beam search. Complements the
    PCFG: PCFG captures *structure*, the Markov model captures *char-level*
    plausibility (e.g. ``p4ss`` vs. ``p@ss``).
    """

    def __init__(self, order: int = 3, beam_width: int = 2000) -> None:
        self.order = order
        self.beam_width = beam_width
        self.transitions: Dict[Tuple[str, ...], Counter] = {}
        self._total = 0

    def train(self, passwords: Sequence[str]) -> "MarkovGuesser":
        for pw in passwords:
            self._train_one(pw)
        return self

    def _train_one(self, password: str) -> None:
        seq = ("<",) * (self.order - 1) + tuple(password) + (">",)
        for i in range(self.order - 1, len(seq)):
            ctx = seq[i - (self.order - 1):i]
            self.transitions.setdefault(ctx, Counter())[seq[i]] += 1
        self._total += 1

    def _probs(self, ctx: Tuple[str, ...]) -> List[Tuple[str, float]]:
        c = self.transitions.get(ctx)
        if not c:
            return []
        total = sum(c.values())
        return [(ch, cnt / total) for ch, cnt in c.most_common()]

    def generate(self, n: int = 100, max_len: int = 16) -> List[Dict[str, float]]:
        if self._total == 0:
            return []
        start = ("<",) * (self.order - 1)
        beam: List[Tuple[str, float]] = [("", 0.0)]  # (prefix, log-prob)
        done: List[Tuple[str, float]] = []
        for _ in range(max_len):
            nxt: List[Tuple[str, float]] = []
            for prefix, logp in beam:
                ctx = (start + tuple(prefix))[-(self.order - 1):]
                for ch, p in self._probs(ctx):
                    if ch == ">":
                        done.append((prefix, logp + math.log(p)))
                    else:
                        nxt.append((prefix + ch, logp + math.log(p)))
            nxt.sort(key=lambda kv: -kv[1])
            beam = nxt[:self.beam_width]
        done.sort(key=lambda kv: -kv[1])
        return [{"password": pw, "prob": round(math.exp(lp), 9)}
                for pw, lp in done[:n]]

    def rank(self, n: int = 100, max_len: int = 16) -> List[Dict[str, float]]:
        return self.generate(n, max_len=max_len)

    def summary(self) -> Dict[str, Any]:
        return {"passwords": self._total, "contexts": len(self.transitions)}
