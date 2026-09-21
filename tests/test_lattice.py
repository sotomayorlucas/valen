"""Tests for the taint lattice (abstract-interpretation layer)."""

from valen.analysis.lattice import TaintLattice, join_all


def test_bottom_is_clean():
    assert TaintLattice.bottom().is_bottom
    assert not TaintLattice.bottom().is_top


def test_partial_order():
    a = TaintLattice(frozenset({"x"}))
    ab = TaintLattice(frozenset({"x", "y"}))
    assert TaintLattice.bottom() <= a
    assert a <= ab
    assert not ab <= a


def test_join_is_union_and_monotone():
    a = TaintLattice(frozenset({"x"}))
    b = TaintLattice(frozenset({"y"}))
    joined = a | b
    assert joined.tags == frozenset({"x", "y"})
    # join is an upper bound of both operands.
    assert a <= joined and b <= joined


def test_meet_is_intersection():
    a = TaintLattice(frozenset({"x", "y"}))
    b = TaintLattice(frozenset({"y", "z"}))
    assert (a & b).tags == frozenset({"y"})


def test_join_all_empty_is_bottom():
    assert join_all([]).is_bottom


def test_sanitizer_maps_to_clean():
    tainted = TaintLattice(frozenset({"input"}))
    assert tainted.clean().is_bottom


def test_lattice_absorption():
    # a | (a & b) == a
    a = TaintLattice(frozenset({"x", "y"}))
    b = TaintLattice(frozenset({"y", "z"}))
    assert (a | (a & b)).tags == a.tags
