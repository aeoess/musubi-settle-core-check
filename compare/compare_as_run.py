import json, os, sys
W = sys.argv[1]
F = ["contract_sha256","verdict","status","bond_outcome","deviation_codes","underspecified_reasons","event_set","dispositions"]
SETS = {"deviation_codes","underspecified_reasons"}
rows, field_agree = [], {f:0 for f in F}
vecs = sorted(os.listdir(f"{W}/sealed/vectors"))
vecs = [v for v in vecs if os.path.isdir(f"{W}/sealed/vectors/{v}")]
for v in vecs:
    exp = json.load(open(f"{W}/sealed/vectors/{v}/expected.json"))
    act = json.load(open(f"{W}/out/{v}.json"))
    diffs = []
    for f in F:
        e, a = exp.get(f, "<absent>"), act.get(f, "<absent>")
        if isinstance(a, str) and a.startswith("UNASSESSED"): diffs.append((f,"UNASSESSED",e,a)); continue
        same = (sorted(set(e)) == sorted(set(a))) if f in SETS and isinstance(e,list) and isinstance(a,list) else e == a
        if same: field_agree[f] += 1
        else: diffs.append((f,"DISAGREE",e,a))
    extra = sorted(set(exp) - set(F))
    rows.append({"vector": v, "all_eight_agree": not diffs, "diffs": diffs, "expected_extra_keys": extra})
json.dump(rows, open(f"{W}/compare/comparison.json","w"), indent=1, sort_keys=True)
print("vectors", len(vecs), "all eight agree", sum(r["all_eight_agree"] for r in rows))
print("per field agreement", field_agree)
for r in rows:
    for f,k,e,a in r["diffs"]:
        print(f"{r['vector']}  {f}  {k}\n   expected: {json.dumps(e)[:300]}\n   actual:   {json.dumps(a)[:300]}")
