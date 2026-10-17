"""kem_expect.py — the one table of expected cycle counts (v0.6.0 link).

Imported by bench_kem.py (VICE, FAILS on any mismatch) and rig_bench.py
(hardware at 1 MHz, which must equal VICE exactly). Cycle counts are
deterministic, so the comparison is exact. Update this file, and only this
file, when a lever changes a count; the README numbers follow from it.

Keys are bench_kem's result names. Inputs are the first ML-KEM-768 vector of
each ACVP group (keyGen tcId 26; encaps and decaps likewise), and for the two
seed rows keyGen tcId 26's d||z with c = Encaps(its ek, the first encaps m).
"""

EXPECTED = {
    "keccak_f1600": 339_688,
    "mlkem_poly_ntt": 579_012,
    "mlkem_poly_intt": 618_210,
    "mlkem_poly_basemul": 308_121,
    "mlkem_keygen": 21_803_250,
    "mlkem_encaps": 24_882_439,
    "mlkem_decaps": 29_600_503,
    "mlkem_decaps_seed": 50_794_288,
    "decaps (same c)": 29_254_338,   # mlkem_decaps on KeyGen(d,z).dk, same c as the seed row
}
