# Changelog

## v0.1.1 (2026-10-13)

Round-2 revisions after first-draft self-review:

- Added 6 test cases (deny wildcard-op, parse_rule rejection paths, rule_covered_by,
  grade C band, recommendations cap) raising the suite from 56 to 62 cases.
- Fixed `test_grade_c_band` to assert the real band boundary (score 63.6 -> C).
- Measured and documented real performance numbers (119.5 ms / 2000-pair audit)
  with a reproducible command; removed all unverified performance claims.

## v0.1.0 (2026-10-13)

First draft:

- Core `audit()` engine: pair enumeration, deny-wins classification, wildcard
  rules (`tool:op` with `*` segments), fixed risk weights, 0-100 score + grade,
  redundant-allow detection, ranked recommendations.
- argparse CLI (`audit` subcommand) with `--json`, `--min-score` gate (exit 1).
- self_test.py inheriting scaffold-v2 four defenses; 56 cases across
  functional / exception / extreme-edge categories; `SUMMARY: PASS n/n` contract.
- README, MIT LICENSE, ALIGNMENT.md.
