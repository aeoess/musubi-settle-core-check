# Ambiguities found while implementing settle core v0 from the text

Each entry: section, the readings, the choice and why. Tags [Ax] appear in settle_core.py.
No expected output was available or consulted. Choices were made from the text and NOTES.md only.

A1. 9.1 / 2.1, contract_sha256 of a contract that is not an object.
Readings: no digest at all, or the prefix plus canonical(value). Chose the second, because 9.1 says contract_sha256 is "always computed". No vector has a non-object contract.

A2. 3.1, canonical form of a non-integer number.
3.1 defines only integers. 6.0 still needs a record_sha256 for a record with a float (it gets a disposition). NOTES N4 says the reference writes Python `repr`. Chose `repr` (0.5 gives `0.5`). NaN and infinities raise. Affects synth_float_in_signed_body, synth_unsigned_float_beside_good, synth_cited_walk_not_strict (the walk's record_sha256). In synth_cited_walk_not_strict the execution's `nenrin_ref` equals the walk digest computed this way, which supports the choice.

A3. 6.0, "an integer too long to write out".
The text gives no limit. Chose the Python default of 4300 decimal digits, since the reference is Python. The parser itself accepts any length. No vector uses it.

A4. 2.3 versus 9.2, whether triage (6.0) runs when 4.1, 4.2 or 5.1 rules 1 to 8 failed.
Reading 1: triage runs on every bound record first (2.3 orders it before the contract and view checks, and lists 6.0 among non-stopping checks). Set aside and rejected records get dispositions, and a strictly signed record with a non-strict body adds `record_not_strict`. Records kept by triage get no disposition (9.2, "never examined").
Reading 2: when 4 or 5 fail, no bound record gets any disposition and triage adds no reason.
Chose reading 1. It affects only vectors where the contract or view fails and a record is set aside or rejected. Among the 76, the halted vectors' records are all kept by triage, so their dispositions are `{}` either way, unless I misjudge one.

A5. 6.4, collapse.
(a) "keep the one with the smallest (height, record_sha256)": smallest among copies that anchor validly, or among all copies. Chose among validly anchoring copies. The other reading lets a junk copy win (real_p31_copy_with_junk_signature_entry), which contradicts N10's stated fix.
(b) "done when section 5 rules 1 to 8 passed, whether or not section 4 did": implemented literally. Collapse runs and assigns `duplicate_dropped` even when the contract failed, but not after 6.2 fails.

A6. 4.1 rules 4 and 5.
"Outer spaces" is read as U+0020 only, stripped after lowercasing, then trailing dots removed. `key_url` is checked as starting with `https://` followed by at least one character. No URL parsing.

A7. 4.1 rule 10, `delegation` "whose only key is allowed" and `ordering` "whose only key is same_height".
Readings: the key must be present, or the object may be empty. Chose keys ⊆ {that key}, with the key optional. No vector has an empty object.

A8. 6.5, witness key lookup when two witnesses share a name.
Used the first witness with that exact name. Such a contract also gets `key_conflict` (4.2), which stops the walk, so the choice cannot change a verdict.

A9. 6.0 versus 10.4, approval signature field.
6.0 says "`sig_b64` (or `signature`)", 10.4 says only `sig_b64`. Chose `sig_b64`, falling back to `signature` only when `sig_b64` is absent, in both places.

A10. 4.3, `grant_subset` (the reference function is normative and NOT specified). THIS IS A GUESS.
Implemented: identical grants (canonical bytes equal) are a subset, which is certain. An added authorized action is a widening, which is certain from 4.3's last paragraph. Everything else is my guess: child prohibited ⊇ parent prohibited; each child conditional action is a parent conditional or parent authorized action; child delegation.allowed ⊆ parent's; data_access ⊆ parent's when the parent has it (absent in the child counts as widening); max_hops and expiry_height ≤ parent's when the parent has them. No comparison of witnesses, finality, privacy, revocation, ordering or approval_policy.
Guard: when the result depends on a guessed part, the implementation reports verdict, status, bond_outcome, deviation_codes and underspecified_reasons as UNASSESSED. On the 76 vectors the guard never fires. synth_parent_supplied_narrows has identical grants, and synth_parent_widened adds the authorized action `write`.
Also from 4.3, I check that `parent_contract.contract_id` equals the parent's `contract_id`. When `parent_contract` is not an object, the narrowing fails.

A11. 6.5, when "ignored" (a revocation whose `revoked_by` is not `"principal"`) is decided.
Chose: after triage and collapse, before conformance and anchors, and only when records are examined (not halted). Reading 2 would put it inside triage, so it would also appear in halted settlements. Only synth_revocation_by_non_principal has such a record, and its contract and view pass, so both readings give the same output there.

A12. 7.6 rule 4, "parses as strict JSON (2.2)" for batch bytes, versus NOTES N4 ("batches are still parsed as the lower layers do").
Chose: duplicate keys and nesting deeper than 512 refuse (`batch_not_json`). Floats are allowed, and `count` is compared with Python equality (so `true` equals 1, per N4). NaN tokens are not JSON and refuse.

A13. 6.6, the `nonconforming_record` deviation for a charged execution that later fails section 7 (for example orphaned).
Chose to keep the deviation, because 6.6 adds it before section 7. No vector combines the two.

A14. 11.1, which executions the cross check reads.
"kept by 6.0, not rejected by 6.6, left after 6.4" is read as the records that enter section 7, whatever their anchor result. The check runs only when records are examined (not halted).

A15. 2.2, `NaN`, `Infinity` and `-Infinity` tokens.
Readings: a parse error (they are not JSON), or non-integer numbers that make a value not strict. Chose parse error, so that input file gives no settlement and every field is UNASSESSED. No vector has them.

A16. 5.1 rule 9 when `view` is not an object or `headers` is not a list.
Chose to add `view_not_strict` as well as `chain_view_rejected`, because the rule 9 condition is not satisfied.

A17. 4.3 `parent_narrowing_failed` when the child fails 4.1 on its own.
The text says "the contract does not pass 4.1 with the parent supplied", so I add it literally, alongside `contract_not_verified`. No vector combines them.

A18. 4.1 rules 13 and 14, non-string entries in `establishes` and `does_not_establish`.
They are ignored, not refused. No vector has them.

A19. 6.6, "a contractor signature that verifies".
Read as plain 3.4 verify (true) by an entry with role `contractor`, not as strict verification. The record is already strictly signed by a party (6.0), so the only difference is a witness signed record that also carries a lax contractor signature.

A20. Section 1, out of scope keys.
The presence of the key (even with value null) is treated as "carries", and all fields except contract_sha256 become UNASSESSED. No vector carries any of them.

A21. 5.1 rule 1, the floor.
Rule 1 asks for a target that decodes. 4.1 rule 10 asks for a positive one. In the view check, I accept any target that decodes.

A22. 10.1, "names this revocation".
The set of names is the body digest hex of the accepted revocation plus the record_sha256 of every bound record with the same record signing bytes, including copies later set aside or dropped. Only synth_delivery_ack_window uses delivery_ack, and it has no acknowledgement records.

A23. 6.6, "the computation is then repeated without the rejected records".
Implemented as a full rerun of triage, 6.2, collapse and conformance, excluding every rejected record so far, until a pass rejects nothing new.

A24. 10.4 step 1, "no principal key".
Read as no party with role `principal` (so no key string to try). A principal key that is unusable fails verification and also gives `forged`.

A25. 10.3 and 6.6, an execution with no `performed_actions`.
It is a conformance problem (a charge if contractor signed), and in the walk it counts as an empty list.

## Places where I suspect my implementation may disagree with the reference

- A4 and A11: dispositions and reasons from triage in settlements where the contract or view already failed.
- A10: any parent case other than identical or authorized-widened grants. The guard reports UNASSESSED there instead of guessing.
- synth_signature_s_plus_l: whether the record is `rejected` or `signature_not_strict` depends on whether OpenSSL's Ed25519 verify accepts S + L. I call the same library and version the spec names (cryptography 50.0.1), which returned false, so my implementation gives `rejected`.
- A2: floats are written with Python `repr`. A JavaScript writer would differ, but the reference is Python.
