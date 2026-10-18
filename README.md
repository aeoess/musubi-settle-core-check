# musubi-settle-core-check

A separately written Python implementation of MUSUBI settle core v0, published as [draft-oga-musubi-settlement-00](https://datatracker.ietf.org/doc/draft-oga-musubi-settlement/), checked against its test vectors.

## Result

| Spec text | Vectors | All eight core fields agree | UNASSESSED | Disagree |
|---|---|---|---|---|
| Revision 0.4, [`dd64d0e2`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/dd64d0e2/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md) | 128 | 128 | 0 | 0 |
| Revision 0.3, [`aea731eb`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/aea731eba556a55571d7c0de9d59641df3cf3713/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md) | 123 | 123 | 0 | 0 |
| Revision 0.2, [`e1c91215`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/e1c912153ad3a55c1a3c4789c1062c53a50fa7b3/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md) | 117 | 117 | 0 | 0 |
| Original, [`4100d52`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/4100d52a42d70d4836c9f6e8d13be188c4a055d8/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0/SETTLE_CORE_v0.md) | 76 | 76 | 0 | 0 |

The eight core fields of section 9.1 (section 10.1 in the draft) are `contract_sha256`, `verdict`, `status`, `bond_outcome`, `deviation_codes`, `underspecified_reasons`, `event_set` and `dispositions`. `deviation_codes` and `underspecified_reasons` are compared as sets, as 9.1 says. The 76 original outputs are byte identical under every version of the code, and the 117 revision 0.2 outputs are byte identical under the revision 0.3 code.

## How it was made, and what that does and does not show

- An AI coding agent wrote `impl/` under my direction. It worked from `SETTLE_CORE_v0.md`, `NOTES.md` and the vector inputs only, first at `4100d52`, then at revision 0.2 (`e1c91215`), then at revision 0.3 (`aea731eb`). It was told not to read the reference code or use the network beyond cloning, and reports that it did not.
- Each input copy had every `expected.json` and `vectors/vectors.json` removed. `INPUT-SHA256SUMS` (259 files), `INPUT-SHA256SUMS-r02` (409 files) and `INPUT-SHA256SUMS-r03` (428 files) list what it saw. `scripts/check_input_clean.sh` checks the copy currently in `input/`.
- Each time, the code and outputs were frozen and hashed before any comparison: `out/FROZEN.txt` (2026-10-17T07:06:06Z), `out/FROZEN-r02.txt` (2026-10-17T17:15:05Z) and `out/FROZEN-r03.txt` (2026-10-18T03:15:57Z). A separate step then compared them with the expected files. For revisions 0.2 and 0.3 the freeze and the comparison are separate commits.
- Revisions 0.2 and 0.3 each agreed on the first run. No fix round was needed.
- Revision 0.4 adds 5 vectors and leaves the 123 earlier vector directories and `inputs/` byte identical (equal git tree hashes at `aea731eb` and `dd64d0e2`). It was run with the revision 0.3 code unchanged, frozen in `out/FROZEN-r04.txt` before the comparison. Before running, I had read the corpus author's comment on #49 that names the reasons the new vectors cover. The code was not changed after reading it.
- Revision 0.3 adds 6 vectors and leaves the 117 earlier vector directories byte identical (equal git tree hashes at `e1c91215` and `aea731eb`).
- Later runs on another machine, from fresh clones of the corpus, reproduced every output file byte for byte.
- This is evidence produced by the implementation's author. It is not a run by an outside party, and the timestamps document the recorded process rather than prove that no other copy of the expected outputs was consulted.
- Revisions 0.2 and 0.3 answer questions this implementation raised, so their text was written partly in response to this code.
- The Agent Passport System, which I maintain, is a party to the contract behind the `real_p31_baseline` vector.

## Coverage limits

- Only the eight core fields are computed. The informative fields of 9.4 and signed settlement packaging are out of scope.
- A contract that carries a well formed `approval_policy.approvers` list, or any other key section 1 puts out of scope, gets UNASSESSED fields. A supplied parent that pins approvers is now decided by 4.3.1 rule 14 (revision 0.3).
- `impl/AMBIGUITIES.md` records the reading the code took wherever the text left a choice: 25 notes for the original text (A1 to A25, most answered in revision 0.2), 10 for revision 0.2 (B1 to B10, answered in revision 0.3 and NOTES.md N15) and 4 for revision 0.3 (C1 to C4). They are implementation notes, not confirmed specification defects.

## Reproduce

Python 3.13 or later and `cryptography` (runs recorded with 50.0.1 and 49.0.0).

Revision 0.4 uses `./scripts/build_input_r04.sh` and `comparison-r04.json` in the same steps as revision 0.3.

Revision 0.3:

```
./scripts/build_input_r03.sh    # clones the corpus at aea731eb, builds input/ and sealed/, checks INPUT-SHA256SUMS-r03
./scripts/check_input_clean.sh  # input/ holds no expected.json or vectors.json
python3 impl/test_primitives.py # 34 primitive tests (32 at the r03 freeze, 2 added by the fix in out/POSTFIX-r03.txt)
python3 impl/run_all.py         # writes out/<vector>.json (overwrites the frozen copies, compare with git diff)
python3 compare/compare.py . comparison-r03.json   # exits 1 on any disagreement, UNASSESSED field or missing output
```

For revision 0.2, use `./scripts/build_input_r02.sh` and `comparison-r02.json` in the same steps.

To run the current checker on the original 76-vector corpus, use:

```
./scripts/build_input.sh
python3 impl/run_all.py
python3 compare/compare.py . comparison-original.json
```

The primitive test suite requires the revision 0.2 or 0.3 input fixtures. Rebuild that input before running the full suite again.

`compare/comparison_as_run.json`, `compare/comparison-r02.json` and `compare/comparison-r03.json` are the comparison results as first run. `compare/compare_as_run.py` is the first comparison script, which reports disagreements but always exits 0, so `compare/compare.py` replaces it as the check.

The corpus itself is not copied here. The build scripts fetch it from the pinned commit.

## License

Apache-2.0 for the code and notes in this repository.
