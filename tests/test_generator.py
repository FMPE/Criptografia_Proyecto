from __future__ import annotations

import math

import pytest

from client.crypto import generator as g
from client.crypto.generator import GeneratorOptions


def test_length_and_all_classes_present():
    for _ in range(200):
        pw = g.generate_password(GeneratorOptions(length=12))
        assert len(pw) == 12
        assert any(c in g.LOWER for c in pw)
        assert any(c in g.UPPER for c in pw)
        assert any(c in g.DIGITS for c in pw)
        assert any(c in g.SYMBOLS for c in pw)


def test_only_digits():
    pw = g.generate_password(GeneratorOptions(length=16, lower=False, upper=False, symbols=False))
    assert pw.isdigit()


def test_avoid_ambiguous():
    opts = GeneratorOptions(length=128, avoid_ambiguous=True)
    for _ in range(20):
        assert not set(g.generate_password(opts)) & g.AMBIGUOUS


def test_passwords_are_unique():
    assert len({g.generate_password() for _ in range(1000)}) == 1000


@pytest.mark.parametrize(
    "opts",
    [
        GeneratorOptions(lower=False, upper=False, digits=False, symbols=False),
        GeneratorOptions(length=4),
        GeneratorOptions(length=1000),
    ],
)
def test_invalid_options(opts):
    with pytest.raises(ValueError):
        g.generate_password(opts)


def test_entropy_estimate():
    opts = GeneratorOptions(length=20)
    alphabet = len(g.LOWER + g.UPPER + g.DIGITS + g.SYMBOLS)
    assert g.estimate_generator_entropy(opts) == pytest.approx(20 * math.log2(alphabet))
    assert g.estimate_generator_entropy(opts) > 120


def test_master_password_meter_orders_sensibly():
    assert g.estimate_password_entropy("aaaaaaaaaaaa") < g.estimate_password_entropy("aB3$kq9!Lm2#")
