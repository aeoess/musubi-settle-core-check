# musubi-settle-core-check

A separately written Python implementation of MUSUBI settle core v0, published as [draft-oga-musubi-settlement-00](https://datatracker.ietf.org/doc/draft-oga-musubi-settlement/), checked against its test vectors.

## Result

| Spec text | Vectors | All eight core fields agree | UNASSESSED | Disagree |
|---|---|---|---|---|
| Revision 0.2, [`e1c91215`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/e1c912153ad3a55c1a3c4789c1062c53a50fa7b3/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md) | 117 | 117 | 0 | 0 |
| Original, [`4100d52`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/4100d52a42d70d4836c9f6e8d13be188c4a055d8/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md) | 76 | 76 | 0 | 0 |

The eight core fields of section 9.1 (section 10.1 in the draft) are `contract_sha256`, `verdict`, `status`, `bond_outcome`, `deviation_codes`, `underspecified_reasons`, `event_set` and `dispositions`. `deviation_codes` and `underspecified_reasons` are compared as sets, as 9.1 says. The 76 original outputs are byte identical under both versions of the code.

## How it was made, and what that does and does not show

- An AI coding agent wrote `impl/` under my direction. It worked from `SETTLE_CORE_v0.md`, `NOTES.md` and the vector inputs only, first at `4100d52`, then at revision 0.2 (`e1c91215`). It was told not to read the reference code or use the network beyond cloning, and reports that it did not.
- Each input copy had every `expected.json` and `vectors/vectors.json` removed. `INPUT-SHA256SUMS` (259 files) and `INPUT-SHA256SUMS-r02` (409 files) list what it saw. `scripts/check_input_clean.sh` checks the second.
- Each time, the code and outputs were frozen and hashed before any comparison: `out/FROZEN.txt` (2026-10-17T07:06:06Z) and `out/FROZEN-r02.txt` (2026-10-17T17:15:05Z). A separate step then compared them with the expected files. The revision 0.2 freeze and comparison are two separate commits.
- Revision 0.2 agreed on the first run. No fix round was needed.
- Later runs on another machine, from fresh clones of the corpus, reproduced every output file byte for byte.
- This is evidence produced by the implementation's author. It is not a run by an outside party, and the timestamps document the recorded process rather than prove that no other copy of the expected outputs was consulted.
- Revision 0.2 answers questions this implementation raised, so its text was written partly in response to this code.
- The Agent Passport System, which I maintain, is a party to the contract behind the `real_p31_baseline` vector.

## Coverage limits

- Only the eight core fields are computed. The informative fields of 9.4 and signed settlement packaging are out of scope.
- One guard remains. A supplied parent whose grant carries `approval_policy.approvers` gets UNASSESSED fields (4.3.1 rule 14, note B5). None of the 117 vectors reaches it.
- `impl/AMBIGUITIES.md` records the reading the code took wherever the text left a choice: 25 notes for the original text (A1 to A25, most now answered in revision 0.2) and 10 for revision 0.2 (B1 to B10). They are implementation notes, not confirmed specification defects.

## Reproduce

Python 3.13 or later and `cryptography` (runs recorded with 50.0.1 and 49.0.0).

Revision 0.2:

```
./scripts/build_input_r02.sh    # clones the corpus at e1c91215, builds input/ and sealed/, checks INPUT-SHA256SUMS-r02
./scripts/check_input_clean.sh  # input/ holds no expected.json or vectors.json
python3 impl/test_primitives.py # 29 primitive tests
python3 impl/run_all.py         # writes out/<vector>.json (overwrites the frozen copies, compare with git diff)
python3 compare/compare.py . comparison-r02.json   # exits 1 on any disagreement, UNASSESSED field or missing output
```

The original 76 use `./scripts/build_input.sh` (corpus at `4100d52`) in place of the first two lines. `compare/comparison_as_run.json` and `compare/comparison-r02.json` are the comparison results as first run. `compare/compare_as_run.py` is the first comparison script, which reports disagreements but always exits 0, so `compare/compare.py` replaces it as the check.

The corpus itself is not copied here. The build scripts fetch it from the pinned commit.

## License

Apache-2.0 for the code and notes in this repository.
