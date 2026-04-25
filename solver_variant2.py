from __future__ import annotations

import base64
import hashlib

from blake3 import blake3


HEX_CHARS = b"0123456789abcdef"


def _b64ud(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


class GunsSolver:
    """Mirror of `new GunsSolver(o09, dd, _org_ts, _n, _2xa)` in gpp_gunslol.js."""

    def __init__(self, _d: str, _dd: int, _h: str, _i: str, _x: str):
        # _d = o09, _dd = dd, _h = _org_ts, _i = _n, _x = _2xa
        blob = _b64ud(_x)
        if blob[:2] != b"\xa1\x40":
            raise ValueError(f"bad _2xa magic: {blob[:2].hex()}")
        if blob[2] != _dd:
            raise ValueError(f"_dd mismatch: blob says {blob[2]}, arg says {_dd}")

        self.dd        = _dd
        self.positions = list(blob[3 : 3 + _dd])
        self.key       = blob[3 + 2 * _dd : 3 + 2 * _dd + 8]
        tmpl_off       = 3 + 2 * _dd + 8
        self.template  = blob[tmpl_off : tmpl_off + (64 - _dd)]
        self.target    = bytes.fromhex(_d)
        self.suffix    = (_i + _h).encode("ascii")

        if len(self.target) != 32:
            raise ValueError(f"o09 must be 64 hex chars, got {len(_d)}")
        if len(_i) != 32 or len(_h) != 10:
            raise ValueError(f"bad _n/_org_ts lengths: {len(_i)}/{len(_h)}")

        self.seal = bytearray(64)
        sorted_pos = sorted(self.positions)
        pos_set = set(sorted_pos)
        t = 0
        for i in range(64):
            if i in pos_set:
                self.seal[i] = 0
            else:
                self.seal[i] = self.template[t]
                t += 1
        self._sorted_pos = sorted_pos

    def solve_pow(self) -> dict:
        dd     = self.dd
        seal   = bytearray(self.seal)
        sorted_pos = self._sorted_pos
        suffix = self.suffix
        target = self.target
        sha256 = hashlib.sha256
        total  = 1 << (4 * dd)

        for n in range(total):
            v = n
            for pos in sorted_pos:
                seal[pos] = HEX_CHARS[v & 0xF]
                v >>= 4
            if sha256(bytes(seal) + suffix).digest() == target:
                solution_chars = bytes(seal[p] for p in self.positions)
                prefix = bytes([0x51, dd]) + solution_chars + b"\x01\x00\x00\x00"
                tag    = blake3(prefix + self.key + target).digest()[:8]
                _oo    = base64.urlsafe_b64encode(prefix + tag).rstrip(b"=").decode("ascii")
                return {"seal": seal.decode("ascii"), "_oo": _oo}

        raise RuntimeError(f"no solution in 16^{dd} space — inputs inconsistent")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 6:
        print(f"usage: {sys.argv[0]} <o09> <dd> <_org_ts> <_n> <_2xa>", file=sys.stderr)
        sys.exit(2)
    o09, dd, _org_ts, _n, _2xa = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
    out = GunsSolver(o09, dd, _org_ts, _n, _2xa).solve_pow()
    print("seal:", out["seal"])
    print("_oo: ", out["_oo"])
