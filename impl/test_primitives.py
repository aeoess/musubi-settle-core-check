"""Unit tests for primitives checkable from the spec text and the real peer31 inputs."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import settle_core as sc  # noqa: E402

P31 = os.path.join(ROOT, "input", "inputs", "peer31")


def load(name):
    with open(os.path.join(P31, name), "rb") as f:
        return sc.parse_json(f.read())


class Canonical(unittest.TestCase):
    def test_rules_3_1(self):
        self.assertEqual(sc.canonical({"b": 1, "a": [True, False, None]}), b'{"a":[true,false,null],"b":1}')
        self.assertEqual(sc.canonical("\x08\x0c\n\r\t\x01\x1f"), b'"\\b\\f\\n\\r\\t\\u0001\\u001f"')
        self.assertEqual(sc.canonical('"\\'), b'"\\"\\\\"')
        self.assertEqual(sc.canonical("\x7f  é"), '"\x7f  é"'.encode("utf-8"))
        self.assertEqual(sc.canonical("\ud800"), b'"\\ud800"')
        self.assertEqual(sc.canonical(-12), b"-12")
        # keys by code point: U+00E9 sorts after 'z'
        self.assertEqual(sc.canonical({"é": 1, "z": 2}), '{"z":2,"é":1}'.encode("utf-8"))

    def test_parser_rules_2_2(self):
        with self.assertRaises(sc.InputError):
            sc.parse_json('{"a":1,"a":2}')
        with self.assertRaises(sc.InputError):
            sc.parse_json("[" * 513 + "]" * 513)
        sc.parse_json("[" * 512 + "]" * 512)
        self.assertIsInstance(sc.parse_json("1.0"), float)
        self.assertIsInstance(sc.parse_json("10"), int)
        self.assertFalse(sc.is_strict_value(sc.parse_json('{"a":1.5}')))
        self.assertFalse(sc.is_strict_value(9007199254740992))
        self.assertTrue(sc.is_strict_value(9007199254740991))
        self.assertFalse(sc.is_strict_value("a\n"))


class Compact(unittest.TestCase):
    def test_5_2(self):
        self.assertEqual(sc.compact_target(0x1D00FFFF), 0xFFFF << (8 * 26))
        self.assertEqual(sc.compact_target(0x207FFFFF), 0x7FFFFF << (8 * 29))
        self.assertEqual(sc.compact_target(0x17080000), 0x080000 << (8 * 20))
        self.assertIsNone(sc.compact_target(0x1D800000 | 1))  # sign bit
        self.assertIsNone(sc.compact_target(0x1D000000))  # zero mantissa
        self.assertEqual(sc.compact_target(0x02123456), 0x123456 >> 8)
        self.assertEqual(sc.compact_target(0x01003456), 0x3456 >> 16)


class Peer31(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = load("c.AB.json")
        cls.e = load("e.anchored.json")
        cls.v = load("view.json")

    def test_contract_sha_and_door(self):
        csha = sc.contract_sha256(self.c)
        self.assertEqual(csha, self.e["contract_ref"]["contract_sha256"])
        self.assertTrue(sc.door(self.c))
        self.assertEqual(sc.terms_reasons(self.c), set())

    def test_contract_signatures(self):
        msg = sc.contract_signing_bytes(self.c)
        for party, sig in zip(self.c["parties"], self.c["signatures"]):
            self.assertEqual(party["domain"], sig["domain"])
            self.assertIs(sc.verify(party["public_key_ed25519_b64"], sig["signature"], msg), True)
            self.assertTrue(sc.strictly_verifies(party["public_key_ed25519_b64"], sig["signature"], msg))
            self.assertIs(sc.verify(party["public_key_ed25519_b64"], sig["signature"], msg + b"x"), False)

    def test_record_signature(self):
        r = sc.Rec(self.e, sc.sha256hex(sc.canonical(self.e)))
        self.assertTrue(sc.strictly_signed(r, self.c))
        self.assertTrue(sc.body_strict(r))
        self.assertTrue(sc.anchor_strict(r))
        self.assertFalse(sc.conformance_problem(r))

    def test_view_and_merkle(self):
        ok, strict9, table, tip = sc.verify_view(self.c, self.v)
        self.assertTrue(ok)
        self.assertTrue(strict9)
        self.assertEqual(table[970190][0], self.c["lower_bound"]["hash"])
        h = self.e["anchor"]["height"]
        self.assertEqual(table[h][0], self.e["anchor"]["block_hash"])
        r = sc.Rec(self.e, sc.sha256hex(sc.canonical(self.e)))
        self.assertTrue(sc.run_proof(r, table[h][1]))
        self.assertIsNone(sc.batch_leg(r))
        self.assertTrue(sc.anchors_validly(r, table))
        # a changed operand breaks the proof
        bad = sc.parse_json(sc.canonical(self.e))
        bad["anchor"]["proof"][0]["hex"] = "00" * 16
        self.assertFalse(sc.run_proof(sc.Rec(bad, "x"), table[h][1]))
        # header hash of the checkpoint recomputed independently
        hx = [x for x in self.v["headers"] if x["height"] == 970190][0]["hex"]
        import hashlib
        hh = hashlib.sha256(hashlib.sha256(bytes.fromhex(hx)).digest()).digest()[::-1].hex()
        self.assertEqual(hh, self.c["lower_bound"]["hash"])


class Points(unittest.TestCase):
    def test_point_checks(self):
        base = bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666")
        self.assertTrue(sc.point_ok(base))
        ident = (1).to_bytes(32, "little")
        self.assertFalse(sc.point_ok(ident))
        # y = p (non-canonical encoding of y = 0)
        self.assertFalse(sc.point_ok((2 ** 255 - 19).to_bytes(32, "little")))
        # small order point of order 4 is y = 0 (x = sqrt(-1))
        self.assertFalse(sc.point_ok((0).to_bytes(32, "little")))
        # order 2 point (0, -1)
        self.assertFalse(sc.point_ok((2 ** 255 - 20).to_bytes(32, "little")))

    def test_s_plus_l_not_strict(self):
        c = load("c.AB.json")
        sig = sc.b64_canonical(c["signatures"][0]["signature"], 64)
        s = int.from_bytes(sig[32:], "little") + sc.L
        mal = sig[:32] + s.to_bytes(32, "little")
        self.assertFalse(sc.sig_bytes_strict(mal))
        self.assertTrue(sc.sig_bytes_strict(sig))

    def test_base64_canonical(self):
        self.assertIsNone(sc.b64_canonical("QQ", None))  # no padding
        self.assertIsNone(sc.b64_canonical("QR==", None))  # non-zero pad bits
        self.assertEqual(sc.b64_canonical("QQ==", None), b"A")


# ------------------------------------------------------------ revision 0.2

VEC = os.path.join(ROOT, "input", "vectors")


def load_vec(vid, name):
    with open(os.path.join(VEC, vid, name), "rb") as f:
        return sc.parse_json(f.read())


def base_grant():
    """A parent grant that sets every axis, used for 4.3.1 rule tests."""
    return {
        "authorized_actions": ["read", "write"],
        "prohibited_actions": ["delete"],
        "conditional": [{"action": "refund", "requires": "principal_approval"}],
        "delegation": {"allowed": ["agent-a"]},
        "data_access": ["db1", "db2"],
        "max_hops": 3,
        "privacy": "private",
        "revocation": {"effective_at": "delivery_ack", "ack_window": 10},
        "finality": {"depth": 6, "max_target_bits": "207fffff"},
        "witnesses": [{"name": "w", "public_key_ed25519_b64": "A" * 43 + "="}],
        "expiry_height": 900000,
        "ordering": {"same_height": "conservative"},
        "approval_policy": {"allow_unscoped": False},
    }


def child_of(p, **chg):
    import copy
    c = copy.deepcopy(p)
    c["max_hops"] = p["max_hops"] - 1
    for k, v in chg.items():
        if v is KeyError:
            c.pop(k, None)
        else:
            c[k] = v
    return c


class Rev02Reading(unittest.TestCase):
    def test_nan_infinity_are_numbers_2_2(self):
        v = sc.parse_json('{"a":NaN,"b":Infinity,"c":-Infinity}')
        self.assertTrue(v["a"] != v["a"])
        self.assertEqual(v["b"], float("inf"))
        self.assertEqual(v["c"], float("-inf"))
        self.assertFalse(sc.is_strict_value(v))
        self.assertEqual(sc.canonical(v), b'{"a":NaN,"b":Infinity,"c":-Infinity}')  # [B2]
        self.assertFalse(sc.numbers_ok_contract({"x": float("nan")}))

    def test_long_integer_token_2_2(self):
        import sys
        self.assertEqual(sys.get_int_max_str_digits(), 4300)  # no global change [B1]
        self.assertEqual(len(str(sc.parse_json("1" * 4300))), 4300)
        sc.parse_json("-" + "1" * 4300)
        with self.assertRaises(sc.InputError):
            sc.parse_json("1" * 4301)
        with self.assertRaises(sc.InputError):
            sc.parse_json("[" + "9" * 5000 + "]")
        sc.parse_json("1" + "0" * 5000 + ".5")  # a non-integer token has no digit limit
        with self.assertRaises(sc.CanonError):
            sc.canonical(10 ** 4300)

    def test_contract_sha256_null_for_non_object_9_1(self):
        self.assertIsNone(sc.contract_sha256([1, 2]))
        out = sc.settle([1, 2], [], {})
        self.assertIsNone(out["contract_sha256"])
        self.assertEqual(out["underspecified_reasons"], ["contract_not_verified"])

    def test_domain_strip_4_1_rule_4(self):
        self.assertEqual(sc.norm_domain("\tPrincipal.Example.com..\n"), "principal.example.com")
        self.assertEqual(sc.norm_domain("\u00a0a.b"), "a.b")  # str.strip() removes NBSP
        self.assertIsNone(sc.norm_domain("a .b"))
        self.assertTrue(sc.door(load_vec("synth_domain_leading_tab", "contract.json")))

    def test_delegation_and_ordering_objects_4_1_rule_10(self):
        self.assertFalse(sc.door(load_vec("synth_delegation_empty_object", "contract.json")))
        self.assertTrue(sc.door(load_vec("synth_ordering_empty_object", "contract.json")))
        c = load_vec("synth_ordering_empty_object", "contract.json")
        c["grant"]["delegation"] = {"allowed": None}
        self.assertFalse(sc.door(c))  # [B3]

    def test_carried_keys_section_1(self):
        self.assertFalse(sc.out_of_scope({"grant": {"limits": None}}))
        self.assertTrue(sc.out_of_scope({"grant": {"limits": {}}}))
        self.assertFalse(sc.out_of_scope({"requirements": {"admission": None}}))
        self.assertTrue(sc.out_of_scope({"requirements": {"admission": {}}}))
        self.assertTrue(sc.out_of_scope({"requirements": {"spine": None}}))
        self.assertTrue(sc.out_of_scope({"requirements": {"convergence": None}}))
        self.assertFalse(sc.out_of_scope({"grant": {"approval_policy": {"approvers": []}}}))
        self.assertFalse(sc.out_of_scope({"grant": {"approval_policy": {"approvers": None}}}))
        # rev 0.3 [B7]: only a well formed approver list is carried
        self.assertFalse(sc.out_of_scope({"grant": {"approval_policy": {"approvers": ["x"]}}}))
        for bad in ({}, "", 0):
            self.assertFalse(sc.out_of_scope({"grant": {"approval_policy": {"approvers": bad}}}))
        c = load_vec("synth_ordering_empty_object", "contract.json")
        c["grant"]["approval_policy"] = {"approvers": []}
        self.assertFalse(sc.door(c))

    def test_approvers_well_formed_4_1_rule_10(self):
        k1 = "A" * 43 + "="
        k2 = "B" * 42 + "A="
        cond = [{"action": "refund"}, {"action": "void", "requires": "x"}]
        e1 = {"name": "a", "public_key_ed25519_b64": k1, "actions": ["refund"]}
        e2 = {"name": "b", "public_key_ed25519_b64": k2, "actions": ["refund", "void"]}
        ok = sc.approvers_well_formed
        self.assertTrue(ok([e1], cond))
        self.assertTrue(ok([e1, e2], cond))
        self.assertTrue(ok([dict(e1, name="n%d" % i, public_key_ed25519_b64=sc.base64.b64encode(bytes([i]) * 32).decode())
                            for i in range(16)], cond))
        self.assertFalse(ok([dict(e1, name="n%d" % i, public_key_ed25519_b64=sc.base64.b64encode(bytes([i]) * 32).decode())
                             for i in range(17)], cond))
        self.assertFalse(ok([], cond))
        self.assertFalse(ok([e1], None))                                   # actions must be in conditional
        self.assertFalse(ok([dict(e1, actions=["other"])], cond))
        self.assertFalse(ok([dict(e1, actions=[])], cond))
        self.assertFalse(ok([dict(e1, actions=["refund", "refund"])], cond))
        self.assertFalse(ok([dict(e1, extra=1)], cond))
        self.assertFalse(ok([{k: v for k, v in e1.items() if k != "actions"}], cond))  # [C1]
        self.assertFalse(ok([dict(e1, name="")], cond))
        self.assertFalse(ok([dict(e1, public_key_ed25519_b64="A" * 43)], cond))    # not canonical
        self.assertFalse(ok([e1, dict(e2, name="a")], cond))               # names unique
        self.assertFalse(ok([e1, dict(e2, public_key_ed25519_b64=k1)], cond))  # keys unique

    def test_rule_14_pinned_approvers_4_3_1(self):
        k1 = "A" * 43 + "="
        e1 = {"name": "a", "public_key_ed25519_b64": k1, "actions": ["refund"]}
        P = {"approval_policy": {"approvers": [e1]}}
        self.assertIn(14, sc.grant_subset_violations({}, P))
        self.assertIn(14, sc.grant_subset_violations({"approval_policy": {}}, P))
        self.assertNotIn(14, sc.grant_subset_violations({"approval_policy": {"approvers": [dict(e1)]}}, P))
        self.assertNotIn(14, sc.grant_subset_violations({}, {}))

    def test_nonfinite_spellings_2_2_b8(self):
        for bad in ("nan", "+Infinity", "infinity", "[nan]", "-nan"):
            with self.assertRaises(sc.InputError):
                sc.parse_json(bad)
        self.assertEqual(sc.parse_json("1e400"), float("inf"))
        self.assertEqual(sc.parse_json("-1e400"), float("-inf"))
        self.assertFalse(sc.is_strict_value({"x": sc.parse_json("1e400")}))
        self.assertEqual(sc.canonical([1.5, 1e16, 1.0]), b"[1.5,1e+16,1.0]")  # 3.1 item 6

    def test_view_not_strict_only_for_object_with_list_5_1_rule_9(self):
        c = load("c.AB.json")
        for v in ([1], {"headers": {}}, {"headers": "x"}, None):
            ok, strict9, _, _ = sc.verify_view(c, v)
            self.assertFalse(ok)
            self.assertTrue(strict9)
        ok, strict9, _, _ = sc.verify_view(c, {"headers": [{"height": 1.5, "hex": "00"}]})
        self.assertFalse(ok)
        self.assertFalse(strict9)

    def test_approval_keys_6_0_and_10_4(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64
        sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        pk = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
        csha = "ab" * 32
        ap = {"contract_sha256": csha, "action": "refund", "valid_until_height": 5,
              "nonce": "cd" * 16, "single_use": True}
        msg = b"a2a-approval-v2\n" + sc.canonical(ap)
        sig = sk.sign(msg)
        good = base64.b64encode(sig).decode()
        s = int.from_bytes(sig[32:], "little") + sc.L
        mal = base64.b64encode(sig[:32] + s.to_bytes(32, "little")).decode()
        self.assertEqual(sc.classify_approval(dict(ap, sig_b64=good), pk, csha, "x", None), "counted")
        self.assertEqual(sc.classify_approval(dict(ap, signature=good), pk, csha, "x", None), "forged")
        self.assertEqual(sc.classify_approval(dict(ap, sig_b64=good, signature=good), pk, csha, "x", None), "counted")
        rec = {"schema": "a2a-execution-v0", "performed_actions": [], "approvals": [dict(ap, sig_b64=good, signature=mal)]}
        self.assertFalse(sc.body_strict(sc.Rec(rec, "x")))
        rec["approvals"] = [dict(ap, sig_b64=mal, signature=good)]
        self.assertFalse(sc.body_strict(sc.Rec(rec, "x")))
        rec["approvals"] = [dict(ap, sig_b64=good, signature=good)]
        self.assertTrue(sc.body_strict(sc.Rec(rec, "x")))


class ParentNarrowing(unittest.TestCase):
    """4.3.1 rules, one per test where possible."""

    def v(self, c, p):
        return sc.grant_subset_violations(c, p)

    def test_baseline_within(self):
        p = base_grant()
        self.assertEqual(self.v(child_of(p), p), [])

    def test_rule_4_max_hops(self):
        p = base_grant()
        self.assertIn(4, self.v(child_of(p, max_hops=3), p))  # copying is not within
        self.assertIn(4, self.v(child_of(p, max_hops=KeyError), p))
        p0 = dict(p, max_hops=0)
        self.assertIn(4, self.v(child_of(p0, max_hops=0), p0))
        q = dict(p)
        q.pop("max_hops")
        self.assertEqual(self.v(dict(child_of(p), max_hops=99), q), [])

    def test_rules_1_2_3_5(self):
        p = base_grant()
        self.assertIn(1, self.v(child_of(p, authorized_actions=["read", "admin"]), p))
        self.assertIn(2, self.v(child_of(p, prohibited_actions=[]), p))
        self.assertIn(3, self.v(child_of(p, data_access=["db3"]), p))
        self.assertEqual(self.v(child_of(p, data_access=KeyError), p), [])
        self.assertEqual(self.v(child_of(p, data_access=None), p), [])
        self.assertIn(5, self.v(child_of(p, delegation={"allowed": ["agent-b"]}), p))

    def test_rule_6_conditional(self):
        p = base_grant()
        self.assertEqual(self.v(child_of(p, conditional=[]), p), [])  # child cannot do refund
        self.assertIn(6, self.v(child_of(p, conditional=[], authorized_actions=["read", "refund"]), p))
        self.assertIn(6, self.v(child_of(p, conditional=[{"action": "refund"}]), p))  # requires differs
        self.assertEqual(self.v(child_of(p, conditional=[], prohibited_actions=["delete", "refund"]), p), [])
        q = dict(p, conditional=[{"action": "refund"}])
        self.assertEqual(self.v(child_of(q, conditional=[{"action": "refund", "requires": None}]), q), [])

    def test_rule_7_and_8(self):
        p = base_grant()
        self.assertIn(7, self.v(child_of(p, conditional=p["conditional"] + [{"action": "pay"}]), p))
        self.assertEqual(self.v(child_of(p, conditional=p["conditional"] + [{"action": "write"}]), p), [])
        self.assertIn(8, self.v(child_of(p, expiry_height=900001), p))
        self.assertIn(8, self.v(child_of(p, expiry_height=KeyError), p))
        self.assertEqual(self.v(child_of(p, expiry_height=1), p), [])

    def test_rule_9_revocation(self):
        p = base_grant()
        self.assertEqual(self.v(child_of(p, revocation={"effective_at": "anchor"}), p), [])
        self.assertIn(9, self.v(child_of(p, revocation={"effective_at": "delivery_ack", "ack_window": 11}), p))
        self.assertIn(9, self.v(child_of(p, revocation={"effective_at": "delivery_ack"}), p))
        self.assertIn(9, self.v(child_of(p, revocation=KeyError), p))
        pa = dict(p, revocation={"effective_at": "anchor"})
        self.assertIn(9, self.v(child_of(pa, revocation={"effective_at": "delivery_ack", "ack_window": 1}), pa))
        pn = dict(p, revocation={"effective_at": "delivery_ack"})
        self.assertEqual(self.v(child_of(pn, revocation={"effective_at": "delivery_ack", "ack_window": 99}), pn), [])

    def test_rule_10_finality(self):
        p = base_grant()
        self.assertEqual(self.v(child_of(p, finality={"depth": 7, "max_target_bits": "1d00ffff"}), p), [])
        self.assertIn(10, self.v(child_of(p, finality={"depth": 5, "max_target_bits": "207fffff"}), p))
        self.assertIn(10, self.v(child_of(p, finality={"depth": 6}), p))
        self.assertIn(10, self.v(child_of(p, finality={"max_target_bits": "207fffff"}), p))
        self.assertIn(10, self.v(child_of(p, finality=KeyError), p))

    def test_rule_11_witness_keys(self):
        p = base_grant()
        k = p["witnesses"][0]["public_key_ed25519_b64"]
        self.assertEqual(self.v(child_of(p, witnesses=[{"name": "other", "public_key_ed25519_b64": k}]), p), [])
        self.assertIn(11, self.v(child_of(p, witnesses=[]), p))
        self.assertIn(11, self.v(child_of(p, witnesses=[{"name": "w", "public_key_ed25519_b64": "B" * 43 + "="}]), p))

    def test_rule_12_privacy_ordering(self):
        p = base_grant()
        self.assertIn(12, self.v(child_of(p, privacy="public"), p))
        self.assertIn(12, self.v(child_of(p, ordering=KeyError), p))
        q = dict(p, ordering={"same_height": None})
        self.assertIn(12, self.v(child_of(q, ordering={}), q))
        r = dict(p, ordering={})
        self.assertIn(12, self.v(child_of(r, ordering={"same_height": None}), r))
        s = dict(p)
        s.pop("privacy")
        self.assertEqual(self.v(child_of(s, privacy="anything"), s), [])

    def test_rule_13_allow_unscoped(self):
        p = base_grant()
        self.assertIn(13, self.v(child_of(p, approval_policy={"allow_unscoped": True}), p))
        pt = dict(p, approval_policy={"allow_unscoped": True})
        self.assertEqual(self.v(child_of(pt, approval_policy={"allow_unscoped": True}), pt), [])

    def test_parent_contract_id_4_3_1(self):
        child = load_vec("synth_parent_full_baseline", "contract.json")
        parent = load_vec("synth_parent_full_baseline", "parent.json")
        self.assertTrue(sc.door(child, parent, with_parent=True))
        c2 = dict(child, parent_contract={})
        self.assertFalse(sc.door(c2, parent, with_parent=True))  # missing contract_id fails


if __name__ == "__main__":
    unittest.main(verbosity=2)
