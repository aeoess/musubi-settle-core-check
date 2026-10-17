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


if __name__ == "__main__":
    unittest.main(verbosity=2)
