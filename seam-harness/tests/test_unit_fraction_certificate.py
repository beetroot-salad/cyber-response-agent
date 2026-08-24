from fractions import Fraction

from seam_harness.unit_fraction_certificate import build_four_term_certificate


def test_four_unit_fractions_half_certificate() -> None:
    certificate = build_four_term_certificate(Fraction(1, 2))

    assert certificate["x_bounds"] == {"minimum": 3, "maximum": 8}
    assert certificate["candidate_y_ranges_by_x"] == {
        "3": {"minimum": 7, "maximum": 18},
        "4": {"minimum": 5, "maximum": 12},
        "5": {"minimum": 5, "maximum": 10},
        "6": {"minimum": 6, "maximum": 9},
        "7": {"minimum": 7, "maximum": 8},
        "8": {"minimum": 8, "maximum": 8},
    }
    assert certificate["candidate_pair_count"] == 33
    assert certificate["totals_by_x"] == {
        "3": 57,
        "4": 28,
        "5": 13,
        "6": 8,
        "7": 1,
        "8": 1,
    }
    assert certificate["grand_total"] == 108
    assert {(row["x"], row["y"]): row["count"] for row in certificate["rows"]}[
        (3, 7)
    ] == 14
    assert len(certificate["rows"]) == 33
