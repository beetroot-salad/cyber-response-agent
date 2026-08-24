# Four unit fractions summing to 1/2: the exact count is 108

**Theorem.** There are exactly **108** quadruples of positive integers x ≤ y ≤ z ≤ w with 1/x + 1/y + 1/z + 1/w = 1/2.

## 1. Finite bounds confining the search

**Lower bound on x.** If x ≤ 2, then 1/x ≥ 1/2 and the other three terms are positive, so the sum exceeds 1/2. Hence x ≥ 3.

**Upper bound on x.** Since x ≤ y, z, w, each term is at most 1/x, so 1/2 = sum ≤ 4/x, giving x ≤ 8.

**Bounds on y for fixed x.** Write the residual r = 1/2 − 1/x − 1/y = 1/z + 1/w. Since z, w ≥ y, we have 0 < r ≤ 2/y. The left inequality gives y > 2x/(x−2); the right gives 1/2 − 1/x ≤ 3/y, i.e. y ≤ 6x/(x−2). Combined with y ≥ x, the exact candidate ranges are:

- x=3: y = 7..18 (r > 0 forces y > 6)
- x=4: y = 5..12 (r > 0 forces y > 4)
- x=5: y = 5..10
- x=6: y = 6..9
- x=7: y = 7..8
- x=8: y = 8

That is 33 candidate pairs. (The packet's 38-pair list also contained (3,3), (3,4), (3,5), (3,6), (4,4); these have r ≤ 0 — for (3,6) and (4,4) the first two terms already sum to 1/2 — so they cannot occur and are excluded.)

## 2. Divisor lemma (exact bijection for the (z,w) count)

For a candidate (x,y), reduce r = (xy − 2x − 2y)/(2xy) = p/q with gcd(p,q)=1. For z ≤ w, 1/z + 1/w = p/q ⟺ pzw = q(z+w). Set u = pz − q, v = pw − q. Since p/q > 1/z, u ≥ 1, and uv = p²zw − pq(z+w) + q² = q². Thus u | q², u ≡ −q (mod p), and u ≤ v ⟺ u ≤ q. Conversely, given u | q² with 1 ≤ u ≤ q and u ≡ −q (mod p), the cofactor v = q²/u automatically satisfies v ≡ −q (mod p) (q is invertible mod p), so z = (u+q)/p and w = (v+q)/p are positive integers solving the equation with z ≤ w. The constraint z ≥ y is exactly u ≥ py − q. Sanity check: r = 1/2 (p,q)=(1,2) gives u ∈ {1,2}, i.e. (z,w) = (3,6),(4,4), count 2.

So the number of (z,w) for each (x,y) equals the number of divisors u of q² with u ≤ q, u ≡ −q (mod p), u ≥ py − q. All arithmetic below is exact integer arithmetic.

## 3. Complete per-(x,y) table

Each entry is `y: (p,q), admissible u, count n`. The admissible-u lists make every count independently checkable: factor q², list divisors ≤ q, apply the congruence and the threshold.

**x = 3 (row total 57)**
- y=7: (1,42), u ∈ {1,2,3,4,6,7,9,12,14,18,21,28,36,42}, n=14
- y=8: (1,24), u ∈ {1,2,3,4,6,8,9,12,16,18,24}, n=11
- y=9: (1,18), u ∈ {1,2,3,4,6,9,12,18}, n=8
- y=10: (1,15), u ∈ {1,3,5,9,15}, n=5
- y=11: (5,66), u ∈ {4,9,44}, n=3
- y=12: (1,12), u ∈ {1,2,3,4,6,8,9,12}, n=8
- y=13: (7,78), u ∈ {13} (u=6 fails z ≥ 13), n=1
- y=14: (2,21), u ∈ {7,9,21}, n=3
- y=15: (1,10), u ∈ {5,10}, n=2
- y=16: (5,48), u ∈ {32}, n=1
- y=17: (11,102), no divisor of 102² below 102 is ≡ 8 (mod 11) and ≥ 85, n=0
- y=18: (1,9), u ∈ {9}, n=1

**x = 4 (row total 28)**
- y=5: (1,20), u ∈ {1,2,4,5,8,10,16,20}, n=8
- y=6: (1,12), u ∈ {1,2,3,4,6,8,9,12}, n=8
- y=7: (3,28), u ∈ {2,8,14}, n=3
- y=8: (1,8), u ∈ {1,2,4,8}, n=4
- y=9: (5,36), u ∈ {9,24}, n=2
- y=10: (3,20), u ∈ {10,16}, n=2
- y=11: (7,44), divisors {1,2,4,8,11,16,22,44}, none ≡ 5 (mod 7), n=0
- y=12: (1,6), u ∈ {6}, n=1

**x = 5 (row total 13)**
- y=5: (1,10), u ∈ {1,2,4,5,10}, n=5
- y=6: (2,15), u ∈ {1,3,5,9,15}, n=5
- y=7: (11,70), u ∈ {7}, n=1
- y=8: (7,40), u ∈ {16}, n=1
- y=9: (17,90), divisors of 90² in [63,90] are 75, 81, 90, none ≡ 12 (mod 17), n=0
- y=10: (1,5), u ∈ {5}, n=1

**x = 6 (row total 8)**
- y=6: (1,6), u ∈ {1,2,3,4,6}, n=5
- y=7: (4,21), u ∈ {7}, n=1
- y=8: (5,24), u ∈ {16}, n=1
- y=9: (2,9), u ∈ {9}, n=1

**x = 7 (row total 1)**
- y=7: (3,14), u ∈ {7}, n=1
- y=8: (13,56), divisors ≤ 56 are {1,2,4,7,8,14,16,28,32,49,56}, none ≡ 9 (mod 13), n=0

**x = 8 (row total 1)**
- y=8: (1,4), u ∈ {4}, n=1

## 4. Grand total and completeness

Grand total: 57 + 28 + 13 + 8 + 1 + 1 = **108**.

Completeness: any solution has 3 ≤ x ≤ 8 by §1, its (x,y) is among the 33 candidate pairs, and for that pair §2's bijection shows its (z,w) appears among the listed admissible u. Zero rows are verified explicitly above. Each quadruple is recoverable as z = (u+q)/p, w = (q²/u + q)/p; e.g. (7,7) with u=7 gives (z,w) = (7,14), and (8,8) with u=4 gives (8,8).
