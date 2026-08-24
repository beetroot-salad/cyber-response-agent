"""Exact certificates for four-term unit-fraction enumeration.

This is a deterministic domain adapter, not a solver agent.  It reduces the
last two denominators to a finite divisor certificate that a proof-producing
agent can cite and a test can verify exactly.
"""

from __future__ import annotations

import argparse
import json
from fractions import Fraction
from math import isqrt
from pathlib import Path
from typing import Any, Sequence


def _divisors(value: int) -> list[int]:
    small: list[int] = []
    large: list[int] = []
    for divisor in range(1, isqrt(value) + 1):
        if value % divisor == 0:
            small.append(divisor)
            if divisor * divisor != value:
                large.append(value // divisor)
    return [*small, *reversed(large)]


def _last_two_certificate(residual: Fraction, minimum: int) -> list[dict[str, int]]:
    """Certify 1/z + 1/w = residual for minimum <= z <= w.

    For residual = p/q in lowest terms,
    (p*z-q)(p*w-q)=q^2.  Enumerating the smaller positive divisor therefore
    enumerates every normalized pair exactly once.
    """

    p, q = residual.numerator, residual.denominator
    witnesses: list[dict[str, int]] = []
    for left in _divisors(q * q):
        right = q * q // left
        if left > right:
            break
        if (left + q) % p or (right + q) % p:
            continue
        z = (left + q) // p
        w = (right + q) // p
        if z < minimum:
            continue
        assert z <= w
        assert Fraction(1, z) + Fraction(1, w) == residual
        witnesses.append({"u": left, "v": right, "z": z, "w": w})
    return witnesses


def build_four_term_certificate(target: Fraction) -> dict[str, Any]:
    if not 0 < target < 1:
        raise ValueError("target must lie strictly between zero and one")

    x_min = max(1, int(Fraction(1, 1) / target) + 1)
    x_max = int(Fraction(4, 1) / target)
    rows: list[dict[str, Any]] = []
    totals: dict[int, int] = {}

    for x in range(x_min, x_max + 1):
        after_x = target - Fraction(1, x)
        if after_x <= 0:
            continue
        y_min = max(x, int(Fraction(1, 1) / after_x) + 1)
        y_max = int(Fraction(3, 1) / after_x)
        for y in range(y_min, y_max + 1):
            residual = after_x - Fraction(1, y)
            if residual <= 0:
                continue
            witnesses = _last_two_certificate(residual, y)
            row = {
                "x": x,
                "y": y,
                "residual_numerator": residual.numerator,
                "residual_denominator": residual.denominator,
                "witnesses": witnesses,
                "count": len(witnesses),
            }
            rows.append(row)
            totals[x] = totals.get(x, 0) + len(witnesses)

    grand_total = sum(totals.values())
    y_ranges: dict[str, dict[str, int]] = {}
    for row in rows:
        key = str(row["x"])
        bounds = y_ranges.setdefault(
            key,
            {"minimum": row["y"], "maximum": row["y"]},
        )
        bounds["minimum"] = min(bounds["minimum"], row["y"])
        bounds["maximum"] = max(bounds["maximum"], row["y"])

    for row in rows:
        for witness in row["witnesses"]:
            x, y, z, w = row["x"], row["y"], witness["z"], witness["w"]
            assert x <= y <= z <= w
            assert (
                sum(
                    (Fraction(1, denominator) for denominator in (x, y, z, w)),
                    Fraction(),
                )
                == target
            )

    return {
        "schema_version": 1,
        "method": (
            "For residual p/q in lowest terms, enumerate positive factor pairs "
            "u*v=q^2 with u<=v, p dividing u+q and v+q, and "
            "z=(u+q)/p >= y; then w=(v+q)/p."
        ),
        "target_numerator": target.numerator,
        "target_denominator": target.denominator,
        "x_bounds": {"minimum": x_min, "maximum": x_max},
        "candidate_y_ranges_by_x": y_ranges,
        "candidate_pair_count": len(rows),
        "rows": rows,
        "totals_by_x": {str(x): total for x, total in totals.items()},
        "grand_total": grand_total,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="1/2")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    certificate = build_four_term_certificate(Fraction(args.target))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(certificate, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
