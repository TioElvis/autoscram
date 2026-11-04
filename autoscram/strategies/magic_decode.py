"""magic-decode strategy: run the multi-decoder on a provided ciphertext.

Useful for "decode this" challenges where the blob is a standard encoding/cipher
(base64, hex, rot13, xor, morse, ...) rather than a binary-specific table. It is
only applicable when you pass --cipher-input and the binary has no cipher_table
(which the `subcipher` strategy handles instead).
"""
from .base import Strategy
from .. import report
from ..magic import magic, FLAG_RE


class MagicDecode(Strategy):
    name = "magic-decode"
    desc = "try common encodings/ciphers on --cipher-input and suggest the chain"
    verifiable = False

    def detect(self, ctx):
        if not getattr(ctx.args, "cipher_input", None):
            return 0, "no --cipher-input provided"
        if ctx.binary.elf.symbols.get("cipher_table") is not None:
            return 0, "binary has cipher_table (subcipher handles it)"
        # user explicitly asked to decode -> take priority over pwn strategies
        return 95, "will brute common encodings on the provided ciphertext"

    def run(self, ctx, io):
        try:
            io.close()
        except Exception:
            pass
        blob = ctx.args.cipher_input.encode()
        results = magic(blob, depth=3, top=8)
        if not results:
            report.warn("magic-decode: nothing decoded")
            return None
        report.ok("candidates (best first):")
        for sc, chain, out in results:
            txt = out.decode("latin-1")
            shown = txt if len(txt) <= 70 else txt[:67] + "..."
            tag = "  <-- FLAG" if FLAG_RE.search(out) else ""
            report.info(f"  score={sc:<5} {' -> '.join(chain):<26} {shown!r}{tag}")
        best = results[0]
        report.ok(f"suggested chain: {' -> '.join(best[1])}")
        m = FLAG_RE.search(best[2])
        if m:
            flag = m.group(0).decode(errors="replace")
            report.ok(f"FLAG: {flag}")
            return flag
        return "MAGIC_NO_FLAG"              # decoded something; stop cleanly
