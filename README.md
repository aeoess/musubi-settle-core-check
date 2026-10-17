# musubi-settle-core-check

A separately written Python implementation of [MUSUBI settle core v0](https://github.com/ogasurfproject-jpg/horizon-shield/blob/4100d52a42d70d4836c9f6e8d13be188c4a055d8/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md) (also [draft-oga-musubi-settlement-00](https://datatracker.ietf.org/doc/draft-oga-musubi-settlement/)), checked against its 76 test vectors.

## Result

All 76 vectors agree with the published `expected.json` on all eight core fields of section 9.1 (section 10.1 in the draft): `contract_sha256`, `verdict`, `status`, `bond_outcome`, `deviation_codes`, `underspecified_reasons`, `event_set`, `dispositions`. `deviation_codes` and `underspecified_reasons` are compared as sets, as 9.1 says.

## How it was made, and what that does and does not show

- An AI coding agent wrote `impl/` under my direction, from `SETTLE_CORE_v0.md` and `NOTES.md` at commit `4100d52` and the vector inputs only. It was told not to read the reference code or the network, and reports that it did not.
- Its input copy had every `expected.json` and `vectors/vectors.json` removed. `INPUT-SHA256SUMS` lists the 259 files it saw.
- The code and outputs were frozen and hashed before any comparison (`out/FROZEN.txt`, 2026-10-17T07:06:06Z). A separate script then compared them with the expected files.
- A later run on another machine, from a fresh clone of the pinned corpus, reproduced all 76 output files byte for byte.
- This is evidence produced by the implementation's author. It is not a run by an outside party, and the timestamps document the recorded process rather than prove that no other copy of the expected outputs was consulted.
- The Agent Passport System, which I maintain, is a party to the contract behind the `real_p31_baseline` vector.

## Coverage limits

- Only the eight core fields are computed. The informative fields of 9.4 and signed settlement packaging are out of scope.
- Section 4.3 leaves the full `grant_subset` rule to the reference. The checker implements identical grants and an added authorized action, and marks the affected fields `UNASSESSED` for any other parent case. None of the 76 vectors reaches that branch.
- `impl/AMBIGUITIES.md` records 25 implementation notes, the reading the code took wherever the text left a choice. Several are resolved by other sections or are documented limits. They are not 25 confirmed specification defects.

## Reproduce

Python 3.13 and `cryptography` 50.0.1.

```
./scripts/build_input.sh        # clones the corpus at 4100d52, builds input/ and sealed/, checks INPUT-SHA256SUMS
python3 impl/test_primitives.py # 10 primitive tests
python3 impl/run_all.py         # writes out/<vector>.json (overwrites the frozen copies, compare with git diff)
python3 compare/compare.py .    # exits 1 on any disagreement or UNASSESSED field
```

`compare/compare_as_run.py` and `compare/comparison_as_run.json` are the comparison script and result as first run. That script reports disagreements but always exits 0, so `compare/compare.py` replaces it as the check.

The corpus itself is not copied here. `scripts/build_input.sh` fetches it from the pinned commit.

## License

Apache-2.0 for the code and notes in this repository.
