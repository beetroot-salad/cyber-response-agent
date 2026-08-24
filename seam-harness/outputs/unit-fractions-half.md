**Theorem.** The triples of positive integers x ≤ y ≤ z satisfying 1/x + 1/y + 1/z = 1/2 are exactly the following ten:

(3,7,42), (3,8,24), (3,9,18), (3,10,15), (3,12,12), (4,5,20), (4,6,12), (4,8,8), (5,5,10), (6,6,6).

**Proof.**

*Step 1: Bounding x.* Since 1/y + 1/z > 0, we must have 1/x < 1/2, so x ≥ 3 (indeed x = 1 gives 1/x = 1 > 1/2 and x = 2 gives 1/x = 1/2, in each case forcing the total strictly above 1/2). Since x ≤ y ≤ z we have 1/x ≥ 1/y ≥ 1/z, hence 1/2 = 1/x + 1/y + 1/z ≤ 3/x, so x ≤ 6. Therefore x ∈ {3, 4, 5, 6}.

*Step 2: The factoring device.* For fixed x the equation reads 1/y + 1/z = (x−2)/(2x), i.e. 2x(y + z) = (x−2)yz. Multiplying by (x−2) and adding 4x² to both sides gives ((x−2)y − 2x)((x−2)z − 2x) = 4x²: every solution corresponds to a factor pair of a fixed positive integer. Since a positive integer has only finitely many factor pairs, inspecting all of them in each case is a complete analysis. In each case below we also use 1/y < 1/y + 1/z = (x−2)/(2x) to bound y from below, which proves the factors are positive, and we impose x ≤ y ≤ z, which corresponds to taking factor pairs A ≤ B with the resulting y ≥ x.

*Case x = 3.* Then 1/y + 1/z = 1/6, i.e. 6y + 6z = yz, i.e. (y−6)(z−6) = 36. Since 1/y < 1/6, we have y > 6, so y−6 ≥ 1 and both factors are positive integers. The divisors of 36 = 2²·3² are 1, 2, 3, 4, 6, 9, 12, 18, 36, so the pairs (d, 36/d) with d ≤ 36/d are exactly (1,36), (2,18), (3,12), (4,9), (6,6). Setting y−6 = d and z−6 = 36/d gives (y,z) = (7,42), (8,24), (9,18), (10,15), (12,12). All have y > 6 ≥ x, so the ordering imposes nothing further: five triples.

*Case x = 4.* Then 1/y + 1/z = 1/4, i.e. 4y + 4z = yz, i.e. (y−4)(z−4) = 16. Since 1/y < 1/4 we have y > 4 and both factors are positive. The divisors of 16 are 1, 2, 4, 8, 16, giving pairs (1,16), (2,8), (4,4), hence (y,z) = (5,20), (6,12), (8,8): three triples.

*Case x = 5.* Then 1/y + 1/z = 3/10, i.e. 10y + 10z = 3yz. Multiplying by 3 and rearranging, (3y−10)(3z−10) = 100. Since 1/y < 3/10 we have y > 10/3, so y ≥ 4 and 3y − 10 ≥ 2 > 0: both factors are positive integers. Moreover 3y − 10 ≡ 2 (mod 3), and likewise 3z − 10 ≡ 2 (mod 3), so only factor pairs of 100 with both entries ≡ 2 (mod 3) can occur. The divisors of 100 = 2²·5² are 1, 2, 4, 5, 10, 20, 25, 50, 100, with residues mod 3 respectively 1, 2, 1, 2, 1, 2, 1, 2, 1. The pairs (d, 100/d) with d ≤ 10 are (1,100), (2,50), (4,25), (5,20), (10,10); only (2,50) and (5,20) have both entries ≡ 2 (mod 3). The pair (2,50) gives y = 12/3 = 4 and z = 60/3 = 20, but y = 4 < 5 = x violates x ≤ y, so it is discarded (its normalization (4,5,20) already appears in the case x = 4). The pair (5,20) gives y = 15/3 = 5 and z = 30/3 = 10: the single triple (5,5,10).

*Case x = 6.* Then 1/y + 1/z = 1/3, i.e. 3y + 3z = yz, i.e. (y−3)(z−3) = 9. Since 1/y < 1/3 we have y > 3, so both factors are positive. The divisors of 9 are 1, 3, 9, giving pairs (1,9) and (3,3). The pair (1,9) gives y = 4 < 6 = x and is discarded (its normalization (4,6,12) appears above). The pair (3,3) gives y = z = 6: the single triple (6,6,6).

*Step 3: Completeness.* Step 1 confines x to {3, 4, 5, 6}. In each case exact integer algebra converts the equation into a factorization of a specific positive integer, positivity of the factors is proved from the equation itself, every factor pair is enumerated from the full divisor list, and the integrality congruence (case x = 5) together with the ordering condition x ≤ y ≤ z is applied pair by pair. No value of x and no factor pair is left unexamined, so the ten triples listed in the theorem are all the solutions.

*Step 4: Direct verification.* Each triple is substituted into 1/x + 1/y + 1/z over a common denominator, in exact arithmetic:

(3,7,42): 14/42 + 6/42 + 1/42 = 21/42 = 1/2.
(3,8,24): 8/24 + 3/24 + 1/24 = 12/24 = 1/2.
(3,9,18): 6/18 + 2/18 + 1/18 = 9/18 = 1/2.
(3,10,15): 10/30 + 3/30 + 2/30 = 15/30 = 1/2.
(3,12,12): 4/12 + 1/12 + 1/12 = 6/12 = 1/2.
(4,5,20): 5/20 + 4/20 + 1/20 = 10/20 = 1/2.
(4,6,12): 3/12 + 2/12 + 1/12 = 6/12 = 1/2.
(4,8,8): 2/8 + 1/8 + 1/8 = 4/8 = 1/2.
(5,5,10): 2/10 + 2/10 + 1/10 = 5/10 = 1/2.
(6,6,6): 1/6 + 1/6 + 1/6 = 3/6 = 1/2.

All ten identities hold, and by Steps 1–3 no further solutions exist. ∎
