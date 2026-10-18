"""Independent implementation of MUSUBI settle core v0, written only from
SETTLE_CORE_v0.md and NOTES.md (revision 0.2, horizon-shield e1c91215).
Standard library plus `cryptography` (Ed25519).

Section numbers in comments refer to SETTLE_CORE_v0.md. Choices made where the
text is ambiguous are listed in AMBIGUITIES.md with the tag [Ax].
"""

import base64
import hashlib
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# [A3][B1] No sys.set_int_max_str_digits call: the interpreter's default limit
# (4300 digits) is left alone for every module in the process. The parser
# refuses longer integer tokens itself (2.2), and canonical() turns the
# interpreter's ValueError into CanonError.
sys.setrecursionlimit(max(sys.getrecursionlimit(), 10000))

SAFE = 2 ** 53 - 1
MAX_DEPTH = 512
INT_DIGIT_LIMIT = 4300  # [A3] 2.2: an integer token longer than this is an error

RECORD_SCHEMAS = {
    "a2a-execution-v0": ("execution", b"a2a-execution-v0\n"),
    "a2a-revocation-v0": ("revocation", b"a2a-revocation-v0\n"),
    "a2a-revocation-ack-v0": ("revocation_ack", b"a2a-revocation-ack-v0\n"),
}

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX8 = re.compile(r"[0-9a-f]{8}")
HEX160 = re.compile(r"[0-9a-f]{160}")
HEX160NL = re.compile(r"[0-9a-f]{160}\n?")
HEXPAIRS = re.compile(r"(?:[0-9a-f]{2})*")
ACTION_RE = re.compile(r"[a-z][a-z0-9_.:-]{0,63}")
LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")


def fm(rx, s):
    return isinstance(s, str) and rx.fullmatch(s) is not None


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


class InputError(Exception):
    pass


class CanonError(Exception):
    pass


# ---------------------------------------------------------------- JSON (2.2)

class _Parser:
    """Strict RFC 8259 parser: duplicate keys and nesting > 512 are errors.
    Integer tokens become int, fraction/exponent tokens become float.
    Optionally records raw character spans of object member values."""

    WS = " \t\n\r"

    def __init__(self, text, spans=False):
        self.t = text
        self.i = 0
        self.depth = 0
        self.spans = {} if spans else None
        self.keep = []

    def err(self, m):
        raise InputError("%s at %d" % (m, self.i))

    def ws(self):
        t, i = self.t, self.i
        while i < len(t) and t[i] in self.WS:
            i += 1
        self.i = i

    def parse(self):
        self.ws()
        v = self.value()
        self.ws()
        if self.i != len(self.t):
            self.err("trailing data")
        return v

    def value(self):
        t = self.t
        if self.i >= len(t):
            self.err("unexpected end")
        c = t[self.i]
        if c == "{":
            return self.obj()
        if c == "[":
            return self.arr()
        if c == '"':
            return self.string()
        if t.startswith("true", self.i):
            self.i += 4
            return True
        if t.startswith("false", self.i):
            self.i += 5
            return False
        if t.startswith("null", self.i):
            self.i += 4
            return None
        # 2.2 (rev 0.2, 0.3) [A15][A12][B8]: exactly these three spellings, case
        # sensitive, are read as non-integer numbers. nan, +Infinity, infinity fall
        # through to number() and are a parse error. 1e400 becomes float inf there.
        if t.startswith("NaN", self.i):
            self.i += 3
            return float("nan")
        if t.startswith("Infinity", self.i):
            self.i += 8
            return float("inf")
        if t.startswith("-Infinity", self.i):
            self.i += 9
            return float("-inf")
        return self.number()

    def number(self):
        m = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?").match(self.t, self.i)
        if not m or m.end() == self.i:
            self.err("bad value")
        tok = m.group(0)
        self.i = m.end()
        if m.group(2) is None and m.group(3) is None:
            # 2.2 (rev 0.2) [A3]: an integer token over 4300 digits is an error
            if len(m.group(1)) > INT_DIGIT_LIMIT:
                self.err("integer token longer than 4300 digits")
            return int(tok)
        return float(tok)

    def string(self):
        t = self.t
        i = self.i + 1
        out = []
        while True:
            if i >= len(t):
                self.err("unterminated string")
            c = t[i]
            if c == '"':
                break
            if c == "\\":
                i += 1
                if i >= len(t):
                    self.err("bad escape")
                e = t[i]
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
                          "n": "\n", "r": "\r", "t": "\t"}
                if e in simple:
                    out.append(simple[e])
                    i += 1
                elif e == "u":
                    h = t[i + 1:i + 5]
                    if not re.fullmatch(r"[0-9a-fA-F]{4}", h):
                        self.err("bad \\u escape")
                    cp = int(h, 16)
                    i += 5
                    if 0xD800 <= cp <= 0xDBFF and t[i:i + 2] == "\\u":
                        h2 = t[i + 2:i + 6]
                        if re.fullmatch(r"[0-9a-fA-F]{4}", h2):
                            cp2 = int(h2, 16)
                            if 0xDC00 <= cp2 <= 0xDFFF:
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (cp2 - 0xDC00)
                                i += 6
                    out.append(chr(cp))
                else:
                    self.err("bad escape")
            else:
                if ord(c) < 0x20:
                    self.err("control character in string")
                out.append(c)
                i += 1
        self.i = i + 1
        return "".join(out)

    def enter(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            self.err("nesting deeper than 512")

    def obj(self):
        self.enter()
        self.i += 1
        d = {}
        sp = {} if self.spans is not None else None
        self.ws()
        if self.t.startswith("}", self.i):
            self.i += 1
        else:
            while True:
                self.ws()
                if not self.t.startswith('"', self.i):
                    self.err("expected key")
                k = self.string()
                if k in d:
                    self.err("duplicate key")
                self.ws()
                if not self.t.startswith(":", self.i):
                    self.err("expected :")
                self.i += 1
                self.ws()
                start = self.i
                d[k] = self.value()
                if sp is not None:
                    sp[k] = (start, self.i)
                self.ws()
                if self.t.startswith(",", self.i):
                    self.i += 1
                    continue
                if self.t.startswith("}", self.i):
                    self.i += 1
                    break
                self.err("expected , or }")
        if sp is not None:
            self.spans[id(d)] = sp
            self.keep.append(d)
        self.depth -= 1
        return d

    def arr(self):
        self.enter()
        self.i += 1
        a = []
        self.ws()
        if self.t.startswith("]", self.i):
            self.i += 1
        else:
            while True:
                self.ws()
                a.append(self.value())
                self.ws()
                if self.t.startswith(",", self.i):
                    self.i += 1
                    continue
                if self.t.startswith("]", self.i):
                    self.i += 1
                    break
                self.err("expected , or ]")
        self.depth -= 1
        return a


def parse_json(data, spans=False):
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            raise InputError("not UTF-8: %s" % e)
    else:
        text = data
    p = _Parser(text, spans)
    v = p.parse()
    if spans:
        return v, p.spans, text
    return v


# ---------------------------------------------------------- canonical (3.1)

def _canon_str(s, out):
    out.append('"')
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append({8: "\\b", 12: "\\f", 10: "\\n", 13: "\\r", 9: "\\t"}.get(o, "\\u%04x" % o))
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)  # lone surrogate
        else:
            out.append(ch)
    out.append('"')


def _canon(v, out, depth):
    if depth > MAX_DEPTH + 1:
        raise CanonError("too deep")
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif is_int(v):
        try:
            out.append(str(v))  # default interpreter limit, 4300 digits [A3][B1]
        except ValueError:
            raise CanonError("integer too long to write out")
    elif isinstance(v, float):
        # 3.1 item 6 (rev 0.3) [A2][B2]: NaN, Infinity, -Infinity, and a finite
        # float as Python's repr. Not nan, not null.
        if v != v:
            out.append("NaN")
        elif v == float("inf"):
            out.append("Infinity")
        elif v == float("-inf"):
            out.append("-Infinity")
        else:
            out.append(repr(v))
    elif isinstance(v, str):
        _canon_str(v, out)
    elif isinstance(v, list):
        out.append("[")
        for n, x in enumerate(v):
            if n:
                out.append(",")
            _canon(x, out, depth + 1)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for n, k in enumerate(sorted(v.keys())):
            if n:
                out.append(",")
            _canon_str(k, out)
            out.append(":")
            _canon(v[k], out, depth + 1)
        out.append("}")
    else:
        raise CanonError("unsupported type")


def canonical(v):
    out = []
    _canon(v, out, 0)
    return "".join(out).encode("utf-8")


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256hex(b):
    return hashlib.sha256(b).hexdigest()


def without(d, *keys):
    return {k: v for k, v in d.items() if k not in keys}


def contract_signing_bytes(contract):
    if isinstance(contract, dict):
        return b"a2a-contract-v0\n" + canonical(without(contract, "signatures"))
    return b"a2a-contract-v0\n" + canonical(contract)  # [A1]


def contract_sha256(contract):
    if not isinstance(contract, dict):
        return None  # 9.1 (rev 0.2) [A1]
    return sha256hex(contract_signing_bytes(contract))


# ------------------------------------------------------------ strict (6.0)

def is_strict_value(v, depth=0):
    if isinstance(v, (dict, list)):
        depth += 1
        if depth > MAX_DEPTH:
            return False
    if isinstance(v, dict):
        for k, x in v.items():
            if any(ord(c) < 0x20 or ord(c) >= 0x7F for c in k):
                return False  # keys: ASCII and no control / DEL
            if not is_strict_value(x, depth):
                return False
        return True
    if isinstance(v, list):
        return all(is_strict_value(x, depth) for x in v)
    if isinstance(v, str):
        return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in v)
    if isinstance(v, bool) or v is None:
        return True
    if is_int(v):
        return -SAFE <= v <= SAFE
    return False  # float


def numbers_ok_contract(v):
    """4.1 rule 11 and rule 12 helpers."""
    if isinstance(v, dict):
        return all(numbers_ok_contract(x) for x in v.values())
    if isinstance(v, list):
        return all(numbers_ok_contract(x) for x in v)
    if isinstance(v, float):
        return False
    if is_int(v):
        return -SAFE <= v <= SAFE
    return True


def keys_printable(v):
    if isinstance(v, dict):
        for k, x in v.items():
            if any(not (0x20 <= ord(c) <= 0x7E) for c in k):
                return False
            if not keys_printable(x):
                return False
        return True
    if isinstance(v, list):
        return all(keys_printable(x) for x in v)
    return True


# ------------------------------------------------------- Ed25519 (3.2, 3.4)

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _pt_add(a, b):
    X1, Y1, Z1, T1 = a
    X2, Y2, Z2, T2 = b
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = 2 * T1 * T2 * D % P
    Dd = 2 * Z1 * Z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _pt_mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _pt_add(q, pt)
        pt = _pt_add(pt, pt)
        s >>= 1
    return q


def _is_identity(pt):
    X, Y, Z, _ = pt
    return X % P == 0 and (Y - Z) % P == 0


def point_ok(b):
    """32 bytes: canonical encoding of a point of prime order, not identity."""
    if len(b) != 32:
        return False
    n = int.from_bytes(b, "little")
    sign = n >> 255
    y = n & ((1 << 255) - 1)
    if y >= P:
        return False
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    if (v * x * x - u) % P != 0:
        if (v * x * x + u) % P == 0:
            x = x * SQRT_M1 % P
        else:
            return False
    if x == 0 and sign == 1:
        return False
    if (x & 1) != sign:
        x = P - x
    pt = (x, y, 1, x * y % P)
    if _is_identity(pt):
        return False
    if not _is_identity(_pt_mul(L, pt)):
        return False
    return True


def b64_canonical(s, n=None):
    if not isinstance(s, str):
        return None
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=True)
    except Exception:
        return None
    if base64.b64encode(raw).decode("ascii") != s:
        return None
    if n is not None and len(raw) != n:
        return None
    return raw


def key_usable(pub_b64):
    raw = b64_canonical(pub_b64, 32)
    if raw is None or not point_ok(raw):
        return None
    return raw


def verify(pub_b64, sig_b64, message):
    """3.4: True, False or 'unusable'."""
    pub = key_usable(pub_b64)
    sig = b64_canonical(sig_b64, 64)
    if pub is None or sig is None:
        return "unusable"
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def sig_bytes_strict(sig):
    return int.from_bytes(sig[32:], "little") < L and point_ok(sig[:32])


def strictly_verifies(pub_b64, sig_b64, message):
    sig = b64_canonical(sig_b64, 64)
    if sig is None or not sig_bytes_strict(sig):
        return False
    return verify(pub_b64, sig_b64, message) is True


# ---------------------------------------------------------- contract (4.1)

ESTABLISHES_BAD = [re.compile(p, re.IGNORECASE) for p in [
    r"\bperformed\b", r"\bdeliver(ed|y)\b", r"\bmoney (moved|was sent)\b",
    r"\bfunds? (moved|were sent|were transferred)\b",
    r"\bpaid\b(?!\s+for\s+(this|the)\s+record)",
    r"\bpayment (was|has been) (made|completed|settled|received)\b",
    r"\bcontract\b", r"\bbinding\b", r"\bguarantee", r"\bescrow\b", r"\bcustody\b",
    r"\bsolvent\b", r"\blawful\b", r"\bfair\b", r"\bcertified\b"]]

GRANT_KEYS = {"authorized_actions", "prohibited_actions", "conditional", "delegation",
              "data_access", "max_hops", "privacy", "revocation", "finality", "witnesses",
              "expiry_height", "ordering", "approval_policy", "limits"}


def norm_domain(d):
    if not isinstance(d, str):
        return None
    d = d.strip().lower()  # 4.1 rule 4 (rev 0.2) [A6]: Python str.strip(), then lowercase
    d = d.rstrip(".")
    if not d or any(c in d for c in "/@: "):
        return None
    labels = d.split(".")
    if len(labels) < 2 or not all(fm(LABEL_RE, x) for x in labels):
        return None
    return d


def compact_target(bits):
    """5.2"""
    exp = bits >> 24
    mant = bits & 0x007FFFFF
    if bits & 0x00800000 or mant == 0:
        return None
    if exp >= 3:
        return mant << (8 * (exp - 3))
    return mant >> (8 * (3 - exp))


def list_of_nonempty_str(v):
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v)


def parties_of(contract):
    """Returns (principal_party, contractor_party) or (None, None)."""
    ps = contract.get("parties") if isinstance(contract, dict) else None
    pr = co = None
    if isinstance(ps, list):
        for p in ps:
            if isinstance(p, dict):
                if p.get("role") == "principal" and pr is None:
                    pr = p
                elif p.get("role") == "contractor" and co is None:
                    co = p
    return pr, co


def door(c, parent=None, with_parent=False):
    """4.1. Returns True when the contract is accepted."""
    if not isinstance(c, dict):
        return False
    if c.get("schema") != "a2a-contract-v0":
        return False
    if not fm(HEX32, c.get("contract_id")) or not fm(HEX32, c.get("nonce")):
        return False
    ps = c.get("parties")
    if not isinstance(ps, list) or len(ps) != 2 or not all(isinstance(p, dict) for p in ps):
        return False
    if sorted([str(p.get("role")) if isinstance(p.get("role"), str) else "" for p in ps]) != ["contractor", "principal"]:
        return False
    doms = []
    for p in ps:
        nd = norm_domain(p.get("domain"))
        if nd is None:
            return False
        doms.append(nd)
        ku = p.get("key_url")
        if not isinstance(ku, str) or not ku.startswith("https://") or len(ku) <= len("https://"):
            return False
        if b64_canonical(p.get("public_key_ed25519_b64"), 32) is None:
            return False
    if doms[0] == doms[1]:
        return False
    task = c.get("task")
    if not isinstance(task, dict) or not isinstance(task.get("purpose"), str) or not task["purpose"]:
        return False
    if task.get("payload_digest") is not None and not fm(HEX64, task.get("payload_digest")):
        return False
    g = c.get("grant")
    if not isinstance(g, dict):
        return False
    if any(k not in GRANT_KEYS for k in g):
        return False
    aa, pa = g.get("authorized_actions"), g.get("prohibited_actions")
    if not list_of_nonempty_str(aa) or not list_of_nonempty_str(pa):
        return False
    if set(aa) & set(pa):
        return False
    # rule 10
    v = g.get("data_access")
    if v is not None and not list_of_nonempty_str(v):
        return False
    for k in ("max_hops", "expiry_height"):
        v = g.get(k)
        if v is not None and not (is_int(v) and v >= 0):
            return False
    v = g.get("delegation")
    if v is not None:
        # 4.1 rule 10 (rev 0.2) [A7][B3]: exactly the key `allowed`, a list of non-empty strings
        if not isinstance(v, dict) or set(v) != {"allowed"} or not list_of_nonempty_str(v["allowed"]):
            return False
    v = g.get("conditional")
    if v is not None:
        if not isinstance(v, list):
            return False
        seen = set()
        for e in v:
            if not isinstance(e, dict) or not isinstance(e.get("action"), str) or not e["action"]:
                return False
            if e["action"] in seen:
                return False
            seen.add(e["action"])
            if "requires" in e and not isinstance(e["requires"], str):
                return False
    v = g.get("finality")
    if v is not None:
        if not isinstance(v, dict) or any(k not in ("depth", "max_target_bits") for k in v):
            return False
        if "depth" in v and not (is_int(v["depth"]) and v["depth"] >= 1):
            return False
        if "max_target_bits" in v:
            mt = v["max_target_bits"]
            if not fm(HEX8, mt):
                return False
            t = compact_target(int(mt, 16))
            if t is None or t <= 0:
                return False
    v = g.get("witnesses")
    if v is not None:
        if not isinstance(v, list):
            return False
        for w in v:
            if not isinstance(w, dict) or not isinstance(w.get("name"), str) or not w["name"]:
                return False
            if b64_canonical(w.get("public_key_ed25519_b64"), 32) is None:
                return False
    v = g.get("privacy")
    if v is not None and not (isinstance(v, str) and v):
        return False
    v = g.get("ordering")
    if v is not None:
        if not isinstance(v, dict) or any(k != "same_height" for k in v):
            return False
        if "same_height" in v and not (v["same_height"] is None or isinstance(v["same_height"], str)):
            return False
    v = g.get("approval_policy")
    if v is not None:
        if not isinstance(v, dict) or any(k not in ("allow_unscoped", "approvers") for k in v):
            return False
        if "allow_unscoped" in v and not isinstance(v["allow_unscoped"], bool):
            return False
        # 4.1 rule 10 and section 1 (rev 0.3) [A20][B7]: approvers, when present,
        # must be a well formed approver list. Any other value, null and [] included,
        # refuses the contract.
        if "approvers" in v and not approvers_well_formed(v["approvers"], g.get("conditional")):
            return False
    v = g.get("revocation")
    if v is not None:
        if not isinstance(v, dict) or v.get("effective_at") not in ("anchor", "delivery_ack"):
            return False
        if any(k not in ("effective_at", "ack_window") for k in v):
            return False
        if "ack_window" in v and not (is_int(v["ack_window"]) and v["ack_window"] >= 1):
            return False
    # rules 11, 12
    if not numbers_ok_contract(c) or not keys_printable(c):
        return False
    # rule 13
    est = c.get("establishes")
    if not isinstance(est, list) or not est:
        return False
    for s in est:
        if isinstance(s, str) and any(rx.search(s) for rx in ESTABLISHES_BAD):
            return False
    # rule 14
    dne = c.get("does_not_establish")
    if not isinstance(dne, list) or not dne:
        return False
    low = [s.lower() for s in dne if isinstance(s, str)]
    groups = [("runtime", "enforce"), ("judge", "liability", "fault"), ("deviat",), ("legal",)]
    for grp in groups:
        if not any(any(w in s for w in grp) for s in low):
            return False
    # rules 15, 16
    sigs = c.get("signatures")
    if not isinstance(sigs, list):
        return False
    msg = contract_signing_bytes(c)
    good = {doms[0]: False, doms[1]: False}
    for s in sigs:
        if not isinstance(s, dict):
            continue
        nd = norm_domain(s.get("domain"))
        if nd is None or nd not in good:
            return False
        party = ps[doms.index(nd)]
        r = verify(party.get("public_key_ed25519_b64"), s.get("signature"), msg)
        if r is not True:
            return False
        good[nd] = True
    if not all(good.values()):
        return False
    if with_parent:
        # 4.3.1: parent_contract is an object whose contract_id equals the parent's
        # (a missing contract_id fails), and the child grant is within the parent's
        pc = c.get("parent_contract")
        if not isinstance(pc, dict) or not isinstance(parent, dict) or "contract_id" not in pc:
            return False
        if pc.get("contract_id") != parent.get("contract_id"):
            return False
        if not grant_subset(c.get("grant"), parent.get("grant")):
            return False
    return True


def _has_int(d, k):
    return isinstance(d, dict) and k in d and is_int(d[k])


def _lst(d, k):
    """4.3.1: a list that is absent or null counts as empty."""
    v = d.get(k) if isinstance(d, dict) else None
    return v if isinstance(v, list) else []


def _sets(d, k):
    """4.3.1: "sets" a key means present with a value other than null."""
    return isinstance(d, dict) and k in d and d[k] is not None


def _obj(d, k):
    v = d.get(k) if isinstance(d, dict) else None
    return v if isinstance(v, dict) else None


def grant_subset_violations(C, P):
    """4.3.1 (rev 0.2). Returns the list of rule numbers that hold (violations).
    Both grants have passed 4.1 rule 10. C is within P when the list is empty."""
    v = []
    # 1
    if any(a not in _lst(P, "authorized_actions") for a in _lst(C, "authorized_actions")):
        v.append(1)
    # 2
    if any(a not in _lst(C, "prohibited_actions") for a in _lst(P, "prohibited_actions")):
        v.append(2)
    # 3
    if any(a not in _lst(P, "data_access") for a in _lst(C, "data_access")):
        v.append(3)
    # 4
    if _has_int(P, "max_hops"):
        p = P["max_hops"]
        if not _has_int(C, "max_hops") or C["max_hops"] > p - 1:
            v.append(4)
    # 5
    if any(a not in _lst(_obj(P, "delegation"), "allowed") for a in _lst(_obj(C, "delegation"), "allowed")):
        v.append(5)
    # 6
    c_cond = [e for e in _lst(C, "conditional") if isinstance(e, dict)]
    c_cond_actions = [e.get("action") for e in c_cond]
    for e in _lst(P, "conditional"):
        if not isinstance(e, dict):
            continue
        a, r = e.get("action"), e.get("requires")  # missing requires is null
        if a in _lst(C, "prohibited_actions"):
            continue
        if a not in _lst(C, "authorized_actions") and a not in c_cond_actions:
            continue
        match = [x for x in c_cond if x.get("action") == a]
        if not match or match[0].get("requires") != r:  # [B4] exact value equality, str or null
            v.append(6)
            break
    # 7
    p_cond_actions = [e.get("action") for e in _lst(P, "conditional") if isinstance(e, dict)]
    if any(a not in _lst(P, "authorized_actions") and a not in p_cond_actions for a in c_cond_actions):
        v.append(7)
    # 8
    if _has_int(P, "expiry_height"):
        if not _has_int(C, "expiry_height") or C["expiry_height"] > P["expiry_height"]:
            v.append(8)
    # 9
    prv = _obj(P, "revocation")
    if prv is not None:
        m = prv.get("effective_at")
        crv = _obj(C, "revocation")
        ok = False
        if crv is not None and "effective_at" in crv:
            ce = crv["effective_at"]
            if m == "anchor":
                ok = ce == "anchor"
            elif m == "delivery_ack":
                if ce == "anchor":
                    ok = True
                elif ce == "delivery_ack":
                    if _has_int(prv, "ack_window"):
                        ok = _has_int(crv, "ack_window") and crv["ack_window"] <= prv["ack_window"]
                    else:
                        ok = True
        if not ok:
            v.append(9)
    # 10
    pf = _obj(P, "finality")
    if pf is not None:
        cf = _obj(C, "finality")
        ok = cf is not None
        if ok and _has_int(pf, "depth"):
            ok = _has_int(cf, "depth") and cf["depth"] >= pf["depth"]
        if ok:
            pt = compact_target(int(pf["max_target_bits"], 16)) if fm(HEX8, pf.get("max_target_bits")) else None
            if pt is not None:
                ct = compact_target(int(cf["max_target_bits"], 16)) if fm(HEX8, cf.get("max_target_bits")) else None
                ok = ct is not None and ct <= pt
        if not ok:
            v.append(10)
    # 11
    pkeys = [w["public_key_ed25519_b64"] for w in _lst(P, "witnesses")
             if isinstance(w, dict) and isinstance(w.get("public_key_ed25519_b64"), str)]
    if pkeys:
        ckeys = [w["public_key_ed25519_b64"] for w in _lst(C, "witnesses")
                 if isinstance(w, dict) and isinstance(w.get("public_key_ed25519_b64"), str)]
        if not ckeys or any(k not in ckeys for k in pkeys):
            v.append(11)
    # 12
    for k in ("privacy", "ordering"):
        if _sets(P, k):
            if not _sets(C, k) or not _json_equal(C[k], P[k]):
                v.append(12)
                break
    # 13
    def unscoped(g):
        ap = _obj(g, "approval_policy")
        return ap is not None and ap.get("allow_unscoped") is True
    if unscoped(C) and not unscoped(P):
        v.append(13)
    # 14 (rev 0.3) [B5][C3]: the pinned approvers differ. Each side's
    # approval_policy.approvers, the empty list when absent, compared as sets of
    # canonical entries (canonical form of each entry object, 3.1).
    def pinned(g):
        ap = _obj(g, "approval_policy")
        a = ap.get("approvers") if ap is not None else None
        return {canonical(e) for e in a} if isinstance(a, list) else set()
    if pinned(C) != pinned(P):
        v.append(14)
    return v


def _json_equal(a, b):
    """Exact JSON value equality (no bool/int confusion)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    return a == b


def grant_subset(child, parent):
    """4.3.1: True when the child grant is within the parent grant."""
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return False
    return not grant_subset_violations(child, parent)


def approvers_well_formed(a, conditional):
    """4.1 rule 10 (rev 0.3) [B7][C1][C2]: a list of 1 to 16 objects, each with keys
    only from name, public_key_ed25519_b64 and actions, all three required: a
    non-empty string name, a canonical 32 byte public_key_ed25519_b64, names and keys
    unique across the list, and actions a non-empty list of distinct non-empty
    strings, each the action of an entry of conditional."""
    if not isinstance(a, list) or not (1 <= len(a) <= 16):
        return False
    cond = set()
    if isinstance(conditional, list):
        for entry in conditional:
            if not isinstance(entry, dict):
                return False
            action = entry.get("action")
            if not isinstance(action, str) or not action:
                return False
            cond.add(action)
    names, keys = set(), set()
    for e in a:
        if not isinstance(e, dict) or any(k not in ("name", "public_key_ed25519_b64", "actions") for k in e):
            return False
        n, k, acts = e.get("name"), e.get("public_key_ed25519_b64"), e.get("actions")
        if not isinstance(n, str) or not n:
            return False
        if b64_canonical(k, 32) is None:
            return False
        if n in names or k in keys:
            return False
        names.add(n)
        keys.add(k)
        if not list_of_nonempty_str(acts) or not acts or len(set(acts)) != len(acts):
            return False
        if any(x not in cond for x in acts):
            return False
    return True


def carries_approvers(c):
    """Section 1 (rev 0.3) [B7]: grant.approval_policy.approvers is carried only when
    it is a well formed approver list (4.1 rule 10). Any other present value is not
    carried, and the door refuses it."""
    g = c.get("grant") if isinstance(c, dict) else None
    ap = g.get("approval_policy") if isinstance(g, dict) else None
    if not isinstance(ap, dict) or "approvers" not in ap:
        return False
    return approvers_well_formed(ap["approvers"], g.get("conditional"))


# ------------------------------------------------------------ terms (4.2)

def terms_reasons(c):
    g = c.get("grant")
    g = g if isinstance(g, dict) else {}
    out = set()
    aa = g.get("authorized_actions")
    if not isinstance(aa, list):
        out.add("authorized_actions_missing")
    names = []
    for k in ("authorized_actions", "prohibited_actions"):
        if isinstance(g.get(k), list):
            names += g[k]
    if isinstance(g.get("conditional"), list):
        names += [e.get("action") for e in g["conditional"] if isinstance(e, dict)]
    if any(not fm(ACTION_RE, n) for n in names):
        out.add("grant_action_name_invalid")
    ws = g.get("witnesses") if isinstance(g.get("witnesses"), list) else []
    if len(ws) > 32:
        out.add("too_many_witnesses")
    wkeys = []
    for w in ws:
        raw = b64_canonical(w.get("public_key_ed25519_b64") if isinstance(w, dict) else None, 32)
        if raw is None:
            out.add("witness_key_invalid")
        else:
            wkeys.append(raw)
    wnames = [w.get("name") for w in ws if isinstance(w, dict)]
    pr, co = parties_of(c)
    keys = []
    for p in (pr, co):
        raw = b64_canonical(p.get("public_key_ed25519_b64"), 32) if p else None
        if raw is not None:
            keys.append(raw)
    keys += wkeys
    if len(set(wnames)) != len(wnames) or len(set(keys)) != len(keys):
        out.add("key_conflict")
    od = g.get("ordering")
    if isinstance(od, dict) and "same_height" in od and od["same_height"] not in (None, "conservative"):
        out.add("tie_policy_refused")
    rv = g.get("revocation")
    if isinstance(rv, dict):
        if rv.get("effective_at") not in ("anchor", "delivery_ack"):
            out.add("revocation_policy_not_recomputable")
        if rv.get("effective_at") == "delivery_ack":
            aw = rv.get("ack_window")
            if not (is_int(aw) and aw >= 1):
                out.add("ack_window_missing")
    fin = g.get("finality")
    dep = fin.get("depth") if isinstance(fin, dict) else None
    if not (is_int(dep) and dep >= 1):
        out.add("finality_policy_missing")
    eh = g.get("expiry_height")
    if eh is not None and not (is_int(eh) and eh >= 0):
        out.add("bad_expiry_height")
    ap = g.get("approval_policy")
    if isinstance(ap, dict) and ap.get("allow_unscoped"):
        out.add("unscoped_approvals_refused")
    return out


def bond_wellformed(b):
    return isinstance(b, dict) and is_int(b.get("amount")) and 1 <= b["amount"] <= SAFE


# -------------------------------------------------------------- view (5.1)

def verify_view(contract, view):
    """Returns (ok_1_to_8, strict_rule9, headers) with headers mapping
    height -> (hash_hex, merkle_root_bytes); and tip."""
    g = contract.get("grant") if isinstance(contract, dict) else None
    fin = g.get("finality") if isinstance(g, dict) else None
    mt = fin.get("max_target_bits") if isinstance(fin, dict) else None
    lb = contract.get("lower_bound") if isinstance(contract, dict) else None
    hs = view.get("headers") if isinstance(view, dict) else None

    # rule 9 (rev 0.2) [A16]: only a view that is an object with a headers list
    # can get view_not_strict; any other view gives chain_view_rejected only
    strict9 = True
    if isinstance(view, dict) and isinstance(hs, list):
        strict9 = is_strict_value(view)
    if strict9 and isinstance(view, dict) and isinstance(hs, list):
        for h in hs:
            if not (isinstance(h, dict) and is_int(h.get("height")) and fm(HEX160, h.get("hex"))):
                strict9 = False
                break

    ok = True
    floor = None
    if fm(HEX8, mt):
        floor = compact_target(int(mt, 16))
    if floor is None:
        ok = False
    if not (isinstance(lb, dict) and is_int(lb.get("height")) and fm(HEX64, lb.get("hash"))):
        ok = False
    if not isinstance(hs, list) or not hs:
        return False, strict9, {}, None
    table = {}
    prev_h = prev_hash = None
    for n, h in enumerate(hs):
        if not (isinstance(h, dict) and is_int(h.get("height")) and h["height"] >= 0
                and fm(HEX160NL, h.get("hex"))):
            return False, strict9, {}, None
        raw = bytes.fromhex(h["hex"][:160])
        height = h["height"]
        if n and height != prev_h + 1:
            ok = False
        hh = sha256(sha256(raw))[::-1].hex()
        if n and raw[4:36][::-1].hex() != prev_hash:
            ok = False
        bits = int.from_bytes(raw[72:76], "little")
        tgt = compact_target(bits)
        if tgt is None or (floor is not None and tgt > floor) or int(hh, 16) > tgt:
            ok = False
        table[height] = (hh, raw[36:68])
        prev_h, prev_hash = height, hh
    if ok:
        if table.get(lb["height"], (None,))[0] != lb["hash"]:
            ok = False
    tip = hs[-1]["height"]
    return ok, strict9, table, tip


# ----------------------------------------------------------- records (6)

class Rec:
    def __init__(self, obj, sha):
        self.obj = obj
        self.sha = sha
        self.schema = obj["schema"]
        self.kind, ctx = RECORD_SCHEMAS[self.schema]
        self.signing = ctx + canonical(without(obj, "signatures", "anchor"))
        self.body_digest = sha256(canonical(without(obj, "anchor")))
        a = obj.get("anchor")
        self.height = a["height"] if isinstance(a, dict) and is_int(a.get("height")) and a["height"] >= 0 else None


def body_strict(r):
    o = r.obj
    body = without(o, "signatures", "anchor")
    if not is_strict_value(body):
        return False
    if "nenrin_ref" in o and o["nenrin_ref"] is not None and not fm(HEX64, o["nenrin_ref"]):
        return False
    ref = o.get("contract_ref")
    if isinstance(ref, dict):
        for k in ("contract_sha256", "payload_digest"):
            if k in ref and not fm(HEX64, ref[k]):
                return False
    if r.kind == "execution":
        for k in ("performed_actions", "delegated_to"):
            if k in o and not (isinstance(o[k], list) and all(isinstance(x, str) for x in o[k])):
                return False
        if "approvals" in o:
            if not (isinstance(o["approvals"], list) and all(isinstance(x, dict) for x in o["approvals"])):
                return False
            for ap in o["approvals"]:
                # 6.0 (rev 0.1): each of sig_b64 and signature is checked on its own
                for key in ("sig_b64", "signature"):
                    if key in ap:
                        raw = b64_canonical(ap[key], 64)
                        if raw is not None and not sig_bytes_strict(raw):
                            return False
    return True


def anchor_strict(r):
    if "anchor" not in r.obj:
        return True
    a = r.obj["anchor"]
    if not is_strict_value(a):
        return False
    if isinstance(a, dict):
        if "block_hash" in a and not fm(HEX64, a["block_hash"]):
            return False
        pr = a.get("proof")
        if isinstance(pr, list):
            for op in pr:
                if isinstance(op, dict) and "hex" in op and not fm(HEXPAIRS, op["hex"]):
                    return False
    return True


def signer_entries(r, contract):
    """Yields (entry, pubkey_b64) for entries with a role the schema allows."""
    pr, co = parties_of(contract)
    g = contract.get("grant") if isinstance(contract, dict) else None
    ws = g.get("witnesses") if isinstance(g, dict) and isinstance(g.get("witnesses"), list) else []
    sigs = r.obj.get("signatures")
    if not isinstance(sigs, list):
        return
    for e in sigs:
        if not isinstance(e, dict):
            continue
        role = e.get("role")
        key = None
        if r.kind == "execution":
            if role == "contractor" and co:
                key = co.get("public_key_ed25519_b64")
            elif role == "witness" and isinstance(e.get("witness_name"), str):
                for w in ws:  # [A8] first witness with that exact name
                    if isinstance(w, dict) and w.get("name") == e["witness_name"]:
                        key = w.get("public_key_ed25519_b64")
                        break
        elif r.kind == "revocation":
            if role == "principal" and pr:
                key = pr.get("public_key_ed25519_b64")
        elif r.kind == "revocation_ack":
            if role == "contractor" and co:
                key = co.get("public_key_ed25519_b64")
        if key is not None:
            yield e, key, role


def strictly_signed(r, contract):
    for e, key, _ in signer_entries(r, contract):
        if is_strict_value(e) and strictly_verifies(key, e.get("sig_b64"), r.signing):
            return True
    return False


def lax_signed(r, contract, role=None):
    for e, key, rl in signer_entries(r, contract):
        if role is not None and rl != role:
            continue
        if verify(key, e.get("sig_b64"), r.signing) is True:
            return True
    return False


def conformance_problem(r):
    o = r.obj
    allowed = {
        "execution": {"schema", "contract_ref", "performed_actions", "approvals", "delegated_to",
                      "nenrin_ref", "outcomes", "anchor", "signatures"},
        "revocation": {"schema", "contract_ref", "revoked_by", "anchor", "signatures"},
        "revocation_ack": {"schema", "contract_ref", "revocation_sha256", "acked_by", "anchor", "signatures"},
    }[r.kind]
    if any(k not in allowed for k in o):
        return True
    if r.kind != "execution":
        return False
    pa = o.get("performed_actions")
    if not (isinstance(pa, list) and all(isinstance(x, str) for x in pa)):
        return True
    oc = o.get("outcomes")
    if oc is not None:
        if not isinstance(oc, dict):
            return True
        for k, v in oc.items():
            if k not in pa or v not in ("ok", "error", "timeout", "partial"):
                return True
    if len(pa) > 256:
        return True
    if any(not fm(ACTION_RE, a) for a in pa):
        return True
    aps = o.get("approvals")
    if isinstance(aps, list):
        for ap in aps:
            if isinstance(ap, dict) and not fm(ACTION_RE, ap.get("action")):
                return True
    return False


# ------------------------------------------------------------- anchors (7)

def run_proof(r, merkle_root):
    a = r.obj.get("anchor")
    pr = a.get("proof") if isinstance(a, dict) else None
    if not isinstance(pr, list) or not pr or len(pr) > 512:
        return False
    cur = r.body_digest
    for op in pr:
        if not isinstance(op, dict):
            return False
        k = op.get("op")
        if k == "sha256":
            cur = sha256(cur)
        elif k == "hexlify":
            cur = cur.hex().encode("ascii")
        elif k in ("append", "prepend"):
            x = op.get("hex")
            if not fm(HEXPAIRS, x) or len(x) // 2 > 4096:
                return False
            xb = bytes.fromhex(x)
            cur = cur + xb if k == "append" else xb + cur
        else:
            return False
        if len(cur) > 65536:
            return False
    return cur == merkle_root


BATCH_SCHEMAS = {"nenrin-agreement-batch-v1", "nenrin-witness-batch-v1", "nenrin-trace-pin-batch-v0"}


def batch_leg(r):
    """7.6. Returns None when accepted, else a refusal code."""
    pr = r.obj["anchor"]["proof"]
    ops = [op.get("op") if isinstance(op, dict) else None for op in pr]
    if "hexlify" not in ops:
        return None
    if ops[0] != "hexlify" or ops.count("hexlify") > 1:
        return "hexlify_not_leading"
    prepends, appends = [], []
    found = False
    for op in pr[1:]:
        k = op.get("op") if isinstance(op, dict) else None
        if k == "sha256":
            found = True
            break
        if k == "prepend":
            prepends.append(bytes.fromhex(op["hex"]))
        elif k == "append":
            appends.append(bytes.fromhex(op["hex"]))
        else:
            return "batch_leg_malformed"
    if not found:
        return "batch_leg_malformed"
    hexd = r.body_digest.hex()
    pre = b"".join(reversed(prepends))
    batch = pre + hexd.encode("ascii") + b"".join(appends)
    try:
        text = batch.decode("utf-8")
        obj, spans, text = parse_json(text, spans=True)
    except (UnicodeDecodeError, InputError, RecursionError):
        return "batch_not_json"
    if not isinstance(obj, dict) or obj.get("schema") not in BATCH_SCHEMAS:
        return "batch_schema_unknown"
    recs = obj.get("records")
    if not isinstance(recs, list) or not all(isinstance(x, dict) for x in recs):
        return "batch_schema_unknown"
    if "count" in obj and obj["count"] != len(recs):  # Python equality [A12]
        return "batch_count_mismatch"
    hits = [x for x in recs if x.get("sha") == hexd]
    if not hits:
        return "record_not_listed_in_batch"
    if len(hits) > 1:
        return "record_listed_twice"
    hit = hits[0]
    if obj.get("schema") == "nenrin-agreement-batch-v1":
        kind = {"a2a-execution-v0": "execution"}.get(r.schema)
        if kind is None:
            return "record_kind_unknown"
        if hit.get("kind") != kind:
            return "record_kind_mismatch"
        if "schema" in hit and hit["schema"] != r.schema:
            return "record_schema_mismatch"
    s, e = spans[id(hit)]["sha"]
    if text[s:e] != '"' + hexd + '"':
        return "internal"
    if len(text[:s + 1].encode("utf-8")) != len(pre):
        return "batch_leg_splice_not_at_listing"
    return None


def anchors_validly(r, table):
    a = r.obj.get("anchor")
    if r.height is None or not isinstance(a, dict) or r.height not in table:
        return False
    hh, root = table[r.height]
    if a.get("block_hash") != hh:
        return False
    if not run_proof(r, root):
        return False
    return batch_leg(r) is None


# ------------------------------------------------------------- settle

def settle(contract, events, view, nenrin_records=None, parent=None, parent_supplied=False):
    """Returns the eight core fields of 9.1. A field may hold a string starting
    with 'UNASSESSED:' where this implementation cannot decide it from the text."""
    if not isinstance(contract, dict):
        # 2.1, 9.1 (rev 0.2) [A1]: contract_sha256 is null
        return _out(contract_sha256(contract), {"contract_not_verified"}, set(), [], {}, "n/a",
                    "underspecified", "undetermined")
    csha = contract_sha256(contract)
    if not isinstance(events, list):
        return _out(csha, {"input_not_settleable"}, set(), [], {}, _bond_pre(contract),
                    "underspecified", "undetermined")

    U, Dv = set(), set()
    disp = {}
    unassessed = {}
    halted = False
    grant = contract.get("grant") if isinstance(contract, dict) else None
    g = grant if isinstance(grant, dict) else {}

    # 4.1, 4.2
    door_ok = door(contract)
    if not door_ok:
        U.add("contract_not_verified")
        halted = True
    else:
        tr = terms_reasons(contract)
        if tr:
            U |= tr
            halted = True
    # 4.3
    sigs = contract.get("signatures")
    if isinstance(sigs, list):
        for s in sigs:
            if isinstance(s, dict):
                raw = b64_canonical(s.get("signature"), 64)
                if raw is not None and not sig_bytes_strict(raw):
                    U.add("contract_signature_not_strict")
    if contract.get("bond") is not None and not bond_wellformed(contract.get("bond")):
        U.add("bond_malformed")
    if contract.get("parent_contract") is not None:
        if not parent_supplied:
            U.add("parent_not_supplied")
        else:
            fail = (not isinstance(parent, dict) or not door(parent)
                    or not door(contract, parent, with_parent=True))
            if fail:
                U.add("parent_narrowing_failed")
            # 4.3.1 rule 14 (rev 0.3) [B5]: a parent that pins approvers is decided by
            # grant_subset_violations rule 14. The old UNASSESSED guard is gone.

    # 5.1
    view_ok, strict9, table, tip = verify_view(contract, view)
    if not view_ok:
        U.add("chain_view_rejected")
        halted = True
    if not strict9:
        U.add("view_not_strict")
    if view_ok and isinstance(view.get("headers"), list) and len(view["headers"]) > 200000:
        U.add("input_too_large")
        halted = True
        view_ok = False

    # 6.1 binding
    cid = contract.get("contract_id")
    task = contract.get("task") if isinstance(contract.get("task"), dict) else {}
    pdg = task.get("payload_digest")
    bound = []
    seen = set()
    for e in events:
        if not isinstance(e, dict) or e.get("schema") not in RECORD_SCHEMAS:
            continue
        try:
            sha = sha256hex(canonical(e))
        except (CanonError, RecursionError):
            continue  # set aside, no disposition (9.2)
        if sha in seen:
            continue
        seen.add(sha)
        ref = e.get("contract_ref") if isinstance(e.get("contract_ref"), dict) else {}
        rs = ref.get("contract_sha256")
        if rs is None:
            if ref.get("contract_id") == cid:
                disp[sha] = "unbound"
            continue
        if not fm(HEX64, rs):
            disp[sha] = "inconsistent"
        elif rs != csha:
            disp[sha] = "foreign"
        elif ref.get("contract_id") != cid:
            disp[sha] = "inconsistent"
        elif pdg is not None and ref.get("payload_digest") != pdg:
            disp[sha] = "inconsistent"
        else:
            bound.append(Rec(e, sha))

    rejected = set()
    while True:
        res = _examine(contract, g, bound, rejected, view_ok, table, tip, halted)
        if res["new_rejected"]:
            rejected |= res["new_rejected"]
            continue
        break

    d2 = dict(disp)
    for sha in rejected:
        d2[sha] = "rejected"
    d2.update(res["disp"])
    U |= res["U"]
    Dv |= res["D"]
    event_set = res["event_set"]
    accepted = res["accepted"]
    orphan_heights = res["orphan_heights"]

    if not halted:
        # 11.1
        survivors = res["survivors"]
        if isinstance(nenrin_records, list) and nenrin_records:
            index, left_out = {}, set()
            for w in nenrin_records:
                try:
                    wsha = sha256hex(canonical(w))
                except (CanonError, RecursionError):
                    continue
                if not is_strict_value(w):
                    left_out.add(wsha)
                elif isinstance(w, dict):
                    index[wsha] = w
            done = set()
            for r in survivors:
                if r.kind != "execution" or r.sha in done:
                    continue
                done.add(r.sha)
                nr = r.obj.get("nenrin_ref")
                if not isinstance(nr, str):
                    continue
                if nr in index:
                    ctx = index[nr].get("context")
                    if isinstance(ctx, dict) and ctx.get("contract_sha256") is not None and ctx["contract_sha256"] != csha:
                        Dv.add("evidence_names_other_contract")
                if nr in left_out:
                    U.add("walk_not_strict")

    # 12 verdict
    if U:
        verdict = "underspecified"
    elif Dv:
        verdict = "deviation"
    elif not event_set:
        verdict = "nothing_to_settle"
    else:
        verdict = "within_grant"
    # 11.2
    req = contract.get("requirements")
    if verdict in ("within_grant", "deviation") and isinstance(req, dict) and req.get("evidence") == "nenrin_required":
        for r in accepted:
            if r.kind == "execution" and not fm(HEX64, r.obj.get("nenrin_ref")):
                Dv.add("evidence_missing")
                verdict = "deviation"

    # 8.5 status
    if verdict == "underspecified":
        status = "undetermined"
    else:
        k = g["finality"]["depth"]
        horizon = tip - k + 1
        hts = [r.height for r in accepted] + orphan_heights
        status = "final" if all(h <= horizon for h in hts) else "provisional"

    bond = _bond(contract, verdict, status)
    es = [{"kind": r.kind, "sha256": r.sha, "height": r.height} for r in event_set]
    out = _out(csha, U if verdict == "underspecified" else set(), Dv if verdict == "deviation" else set(),
               es, d2, bond, verdict, status)
    out.update(unassessed)
    return out


def _bond_pre(contract):
    b = contract.get("bond")
    if b is None:
        return "n/a"
    if isinstance(b, dict) and b.get("amount"):
        return "undetermined"
    return "n/a"


def _bond(contract, verdict, status):
    b = contract.get("bond")
    if b is None:
        return "n/a"
    if not bond_wellformed(b):
        return "undetermined" if isinstance(b, dict) and b.get("amount") else "n/a"
    if verdict == "underspecified":
        return "undetermined"
    if status == "provisional":
        return "pending_finality"
    return "forfeited" if verdict == "deviation" else "held"


def _out(csha, U, Dv, es, disp, bond, verdict, status):
    return {
        "contract_sha256": csha,
        "verdict": verdict,
        "status": status,
        "bond_outcome": bond,
        "deviation_codes": sorted(Dv),
        "underspecified_reasons": sorted(U),
        "event_set": es,
        "dispositions": disp,
    }


def _examine(contract, g, bound, rejected, view_ok, table, tip, halted):
    """One pass of 6.0, 6.2, 6.4, 6.5, 6.6 and 7 over bound records not yet rejected."""
    U, D = set(), set()
    disp = {}
    new_rej = set()
    recs = [r for r in bound if r.sha not in rejected]
    revocable = isinstance(g.get("revocation"), dict)

    # 6.0 triage, first pass: everything but the sibling rule
    pre = {}
    for r in recs:
        ss = strictly_signed(r, contract)
        bs = body_strict(r)
        if not ss:
            if not bs:
                pre[r.sha] = ("aside", "record_not_strict")
            elif lax_signed(r, contract):
                pre[r.sha] = ("aside", "signature_not_strict")
            else:
                pre[r.sha] = ("rejected", None)
        elif not bs:
            pre[r.sha] = ("closed", "record_not_strict")
        elif not anchor_strict(r):
            pre[r.sha] = ("anchor", None)
        elif r.kind == "revocation" and not revocable:
            pre[r.sha] = ("aside", "revocation_not_provided_for")
        else:
            pre[r.sha] = ("kept", None)
    kept = [r for r in recs if pre[r.sha][0] == "kept"]
    for r in recs:
        st, code = pre[r.sha]
        if st == "aside":
            disp[r.sha] = code
        elif st == "rejected":
            new_rej.add(r.sha)
        elif st == "closed":
            disp[r.sha] = code
            U.add(code)
        elif st == "anchor":
            sib = view_ok and any(k.signing == r.signing and anchors_validly(k, table) for k in kept)
            disp[r.sha] = "anchor_not_strict"
            if not sib:
                U.add("anchor_not_strict")

    result = {"U": U, "D": D, "disp": disp, "new_rejected": new_rej, "event_set": [],
              "accepted": [], "orphan_heights": [], "survivors": []}
    if new_rej:
        return result

    # 6.2
    if len(kept) > 10000:
        U.add("input_too_large")
        return result

    # 6.4 collapse (when 5.1 rules 1-8 passed)
    survivors = list(kept)
    if view_ok:
        groups = {}
        for r in kept:
            groups.setdefault(r.signing, []).append(r)
        survivors = []
        for r in kept:
            grp = groups[r.signing]
            if len({x.sha for x in grp}) <= 1:
                survivors.append(r)
                continue
            valid = [x for x in grp if anchors_validly(x, table)]
            if not valid:
                survivors.append(r)
                continue
            best = min(valid, key=lambda x: (x.height, x.sha))
            if r is best:
                survivors.append(r)
            else:
                disp[r.sha] = "duplicate_dropped"
    after_collapse = list(survivors)  # 10.1 (rev 0.2) [A22][B6]
    if halted:
        return result

    # 6.5 ignored revocations
    s2 = []
    for r in survivors:
        if r.kind == "revocation" and r.obj.get("revoked_by") != "principal":
            disp[r.sha] = "ignored"
        else:
            s2.append(r)
    survivors = s2

    # 6.6 conformance
    s3 = []
    for r in survivors:
        if conformance_problem(r):
            if r.kind == "execution" and lax_signed(r, contract, role="contractor"):
                D.add("nonconforming_record")
                s3.append(r)
            else:
                new_rej.add(r.sha)
        else:
            s3.append(r)
    if new_rej:
        return result
    survivors = s3
    result["survivors"] = survivors

    # 7 anchors
    lbh = contract["lower_bound"]["height"]
    accepted, orphans = [], []
    for r in survivors:
        a = r.obj.get("anchor")
        if r.height is None or not fm(HEX64, a.get("block_hash") if isinstance(a, dict) else None):
            code = "anchor_incomplete"
        elif r.height < lbh:
            code = "anchor_below_lower_bound"
        elif r.height > tip or r.height not in table:
            code = "anchor_beyond_observed_chain"
        elif a["block_hash"] != table[r.height][0]:
            disp[r.sha] = "orphaned"
            orphans.append(r.height)
            continue
        elif not run_proof(r, table[r.height][1]):
            code = "anchor_proof_invalid"
        elif batch_leg(r) is not None:
            code = "anchor_batch_leg_refused"
        else:
            disp[r.sha] = "accepted"
            accepted.append(r)
            continue
        disp[r.sha] = code
        U.add(code)

    # 8.1
    es = sorted(accepted, key=lambda r: (r.height, r.sha))
    result["event_set"] = es
    result["accepted"] = accepted
    result["orphan_heights"] = orphans

    # 10 grant evaluation
    D |= walk_grant(contract, g, es, after_collapse)
    return result


def walk_grant(contract, g, es, after_collapse):
    D = set()
    csha = contract_sha256(contract)
    rv = g.get("revocation") if isinstance(g.get("revocation"), dict) else {}
    # 10.1
    acks = [r for r in es if r.kind == "revocation_ack"]
    effs = []
    for r in es:
        if r.kind != "revocation":
            continue
        if rv.get("effective_at") == "anchor":
            E = r.height
        else:
            # 10.1 (rev 0.2) [A22]: body digest, or the record_sha256 of a copy still in
            # the input after 6.4 (a copy 6.4 dropped no longer names it)
            names = {r.body_digest.hex()} | {b.sha for b in after_collapse if b.signing == r.signing}
            cands = [r.height + rv["ack_window"]]
            cands += [a.height for a in acks if a.obj.get("revocation_sha256") in names]
            E = min(cands)
        effs.append((E, r.sha))
    effs.sort()

    pr, _ = parties_of(contract)
    pk = pr.get("public_key_ed25519_b64") if pr else None
    task = contract.get("task") if isinstance(contract.get("task"), dict) else {}

    # 10.4 classify approvals of every accepted execution
    counted = []  # (record, approval) in event set order
    for r in es:
        if r.kind != "execution":
            continue
        aps = r.obj.get("approvals")
        for ap in (aps if isinstance(aps, list) else []):
            cls = classify_approval(ap, pk, csha, contract.get("contract_id"), task.get("payload_digest"))
            if cls == "forged":
                D.add("forged_approval")
            elif cls == "counted":
                counted.append((r, ap))

    prohibited = g.get("prohibited_actions") if isinstance(g.get("prohibited_actions"), list) else []
    authorized = g.get("authorized_actions") if isinstance(g.get("authorized_actions"), list) else []
    conditional = [e.get("action") for e in (g.get("conditional") or []) if isinstance(e, dict)]
    deleg = g.get("delegation")
    allowed = (deleg.get("allowed") or []) if isinstance(deleg, dict) else []
    expiry = g.get("expiry_height")
    consumed = set()

    for r in es:
        if r.kind != "execution":
            continue
        h = r.height
        pa = r.obj.get("performed_actions")
        pa = [a for a in pa if isinstance(a, str)] if isinstance(pa, list) else []
        if any(E <= h for E, _ in effs):
            if pa:
                D.add("revoked")
            continue
        for a in pa:
            if expiry is not None and h > expiry:
                D.add("after_expiry")
            if a in prohibited:
                D.add("prohibited")
            elif a in conditional:
                used = None
                for (cr, ap) in counted:
                    if ap.get("action") != a:
                        continue
                    if not (cr.sha == r.sha or cr.height < h):
                        continue
                    if not (h <= ap["valid_until_height"]):
                        continue
                    if ap["single_use"] is True and ap["nonce"] in consumed:
                        continue
                    used = ap
                    break
                if used is None:
                    D.add("conditional")
                elif used["single_use"] is True:
                    consumed.add(used["nonce"])
            elif a not in authorized:
                D.add("unauthorized")
        dt = r.obj.get("delegated_to")
        for d in (dt if isinstance(dt, list) else []):
            if d not in allowed:
                D.add("delegation")
    return D


def classify_approval(ap, pk, csha, cid, pdg):
    if not isinstance(ap, dict) or pk is None:
        return "forged"
    sig = ap.get("sig_b64")  # 10.4 (rev 0.1) [A9]: only sig_b64 is verified
    vuh, nonce, su, acs = ap.get("valid_until_height"), ap.get("nonce"), ap.get("single_use"), ap.get("contract_sha256")
    fields = is_int(vuh) and vuh >= 0 and fm(HEX32, nonce) and isinstance(su, bool)
    if fields and fm(HEX64, acs):
        msg = b"a2a-approval-v2\n" + canonical({"contract_sha256": acs, "action": ap.get("action"),
                                                 "valid_until_height": vuh, "nonce": nonce, "single_use": su})
        if verify(pk, sig, msg) is True:
            return "counted" if acs == csha else "other_terms"
    if fields:
        msg = b"a2a-approval-v1\n" + canonical({"contract_id": cid, "payload_digest": pdg, "action": ap.get("action"),
                                                 "valid_until_height": vuh, "nonce": nonce, "single_use": su})
        if verify(pk, sig, msg) is True:
            return "label_bound"
    msg = b"a2a-approval-v0\n" + canonical({"contract_id": cid, "payload_digest": pdg, "action": ap.get("action")})
    if verify(pk, sig, msg) is True:
        return "label_bound"
    return "forged"


OUT_OF_SCOPE = "UNASSESSED: contract carries a key outside core v0 scope (section 1)"


def out_of_scope(contract):
    """Section 1 (rev 0.2, 0.3) [A20][B7]. A key is carried when present with a value
    other than null. Spine and convergence are carried whenever present. Approvers are
    carried only as a well formed approver list (any other value is refused by the door)."""
    if not isinstance(contract, dict):
        return False
    req = contract.get("requirements")
    g = contract.get("grant")
    if isinstance(req, dict):
        if "spine" in req or "convergence" in req:
            return True
        if req.get("admission") is not None:
            return True
    if isinstance(g, dict):
        if g.get("limits") is not None:
            return True
        if carries_approvers(contract):
            return True
    return False
