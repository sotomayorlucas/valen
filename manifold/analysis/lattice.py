"""Algebraic layer: the taint lattice (abstract interpretation).

We formalize taint analysis as an *abstract interpretation* over a bounded
lattice. Each taint tag (source name) is an atomic attribute; the abstract
domain is the powerset lattice of tags ordered by subset inclusion.

    clean  = bottom (empty set)   <->  no taint
    tainted = top (all tags)       <->  maximally tainted

A program statement is a monotone transfer function over this lattice, and the
fixed point over a control-flow graph is a sound over-approximation of all
taint flows (Galois connection (alpha, gamma) between the concrete collecting
semantics and this abstract domain).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Generic, Iterable, Set, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class TaintLattice(Generic[T]):
    """The powerset lattice of taint tags.

    * bottom ``{}`` is ``clean``.
    * ``join`` is set union (least upper bound), used when control flow merges.
    * ``meet`` is set intersection (greatest lower bound), used by *sanitizers*
      (which map any value to ``clean``) and by trust checks.
    """

    tags: FrozenSet[T] = frozenset()

    @property
    def is_bottom(self) -> bool:
        return not self.tags

    @property
    def is_top(self) -> bool:
        # Top is the universe; we approximate "top" as the set of all currently
        # tracked tags, which is what the powerset lattice over a finite tag set
        # provides. A value is "tainted" iff it is not bottom.
        return not self.is_bottom

    def __le__(self, other: "TaintLattice[T]") -> bool:
        """Partial order: self is *less* tainted than or equal to other."""
        return self.tags <= other.tags

    def __or__(self, other: "TaintLattice[T]") -> "TaintLattice[T]":
        """Join (least upper bound)."""
        return TaintLattice(self.tags | other.tags)

    def __and__(self, other: "TaintLattice[T]") -> "TaintLattice[T]":
        """Meet (greatest lower bound)."""
        return TaintLattice(self.tags & other.tags)

    def clean(self) -> "TaintLattice[T]":
        """The sanitizer transfer: map any value to bottom (clean)."""
        return TaintLattice(frozenset())

    def with_tags(self, tags: Iterable[T]) -> "TaintLattice[T]":
        return TaintLattice(frozenset(tags) | self.tags)

    @classmethod
    def bottom(cls) -> "TaintLattice[T]":
        return cls(frozenset())

    @classmethod
    def top(cls, tags: Iterable[T]) -> "TaintLattice[T]":
        return cls(frozenset(tags))

    def __repr__(self) -> str:
        return f"TaintLattice({sorted(self.tags)})"


def join_all(lattices: Iterable[TaintLattice[T]]) -> TaintLattice[T]:
    """Least upper bound of a set of lattice elements (empty join is bottom)."""
    acc: Set[T] = set()
    for lat in lattices:
        acc |= lat.tags
    return TaintLattice(frozenset(acc))
