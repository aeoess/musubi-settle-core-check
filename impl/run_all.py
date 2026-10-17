"""Run settle_core over every vector in input/vectors/ and write out/<id>.json.
Reads only input/. Writes only out/."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import settle_core as sc  # noqa: E402

VEC = os.path.join(ROOT, "input", "vectors")
OUT = os.path.join(ROOT, "out")
FIELDS = ["contract_sha256", "verdict", "status", "bond_outcome", "deviation_codes",
          "underspecified_reasons", "event_set", "dispositions"]


def load(path):
    with open(path, "rb") as f:
        return sc.parse_json(f.read())


def load_dir(d):
    if not os.path.isdir(d):
        return []
    return [load(os.path.join(d, n)) for n in sorted(os.listdir(d)) if n.endswith(".json")]


def run_one(vid):
    vd = os.path.join(VEC, vid)
    try:
        contract = load(os.path.join(vd, "contract.json"))
        view = load(os.path.join(vd, "view.json"))
        events = load_dir(os.path.join(vd, "events"))
        nen = load_dir(os.path.join(vd, "nenrin")) if os.path.isdir(os.path.join(vd, "nenrin")) else None
        pp = os.path.join(vd, "parent.json")
        has_parent = os.path.exists(pp)
        parent = load(pp) if has_parent else None
    except sc.InputError as e:
        # 2.2: an input that is not valid JSON under the extra rules gives no settlement
        return {f: "UNASSESSED: input not readable under 2.2 (%s); no settlement is produced" % e for f in FIELDS}
    if sc.out_of_scope(contract):
        res = {f: sc.OUT_OF_SCOPE for f in FIELDS}
        res["contract_sha256"] = sc.contract_sha256(contract)
        return res
    return sc.settle(contract, events, view, nenrin_records=nen, parent=parent, parent_supplied=has_parent)


def main():
    os.makedirs(OUT, exist_ok=True)
    ids = sorted(n for n in os.listdir(VEC) if os.path.isdir(os.path.join(VEC, n)))
    for vid in ids:
        res = run_one(vid)
        with open(os.path.join(OUT, vid + ".json"), "wb") as f:
            f.write(sc.canonical({k: res[k] for k in FIELDS}))
    print("wrote %d vectors" % len(ids))


if __name__ == "__main__":
    main()
