"""Substitution-cipher decoder (e.g. an emoji cipher).

Some challenges ship a *tool*, not a flag: the binary maps each plaintext byte
to a token (an emoji, a word, a glyph) via a table and decodes whatever you
feed it. There is no embedded flag to extract -- the ciphertext comes from the
challenge (its description or an attachment).

This strategy reconstructs the substitution table from the binary (by symbol,
or by scanning data when the binary is stripped), tells you *what kind of cipher
it is*, writes the full mapping out, and -- given the ciphertext via
`--cipher-input` -- decodes it to the flag, chaining the multi-decoder in case
the result is itself encoded.
"""
import os
import re

from .base import Strategy
from .. import report
from ..cipher import (reconstruct_table, decode, invert, classify,
                      find_table_by_scan)
from ..magic import magic, FLAG_RE

_CIPHER_RE = re.compile(r"cipher|decipher|decode|encode|substitut", re.I)
_SAMPLE = 12


def _readers(binary):
    """Build the (read, in_mapped, in_rodata) callables cipher.py needs."""
    elf = binary.elf

    def read(addr, n):
        try:
            return elf.read(addr, n)
        except Exception:
            return b""

    def _seg(addr):
        for seg in elf.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue
            lo = seg.header.p_vaddr
            if lo <= addr < lo + seg.header.p_memsz:
                return seg
        return None

    def in_mapped(addr):
        return _seg(addr) is not None

    def in_rodata(addr):
        seg = _seg(addr)
        return seg is not None and not (seg.header.p_flags & 2)   # not PF_W

    return read, in_mapped, in_rodata


def _data_sections(binary):
    out = []
    for sec in binary.elf.iter_sections():
        try:
            if (sec["sh_flags"] & 0x2) and not (sec["sh_flags"] & 0x4) \
                    and sec["sh_type"] == "SHT_PROGBITS" and sec["sh_size"]:
                out.append((sec["sh_addr"], sec["sh_size"]))
        except Exception:
            continue
    return out


class SubstitutionCipher(Strategy):
    name = "subcipher"
    desc = "reconstruct a substitution table, suggest the cipher, decode it"
    verifiable = False               # no embedded flag; nothing to self-test

    def _table(self, binary):
        """Return the table address: by symbol first, then by scanning data."""
        addr = binary.elf.symbols.get("cipher_table")
        if addr is not None:
            return addr, "symbol 'cipher_table'"
        for n, a in binary.elf.symbols.items():
            if "table" in n.lower() and not binary.in_executable(a):
                return a, f"symbol '{n}'"
        read, in_mapped, in_rodata = _readers(binary)
        found = find_table_by_scan(read, in_mapped, in_rodata,
                                   _data_sections(binary))
        if found is not None:
            return found, "scan of data sections"
        return None, "none"

    def detect(self, ctx):
        b = ctx.binary
        addr, how = self._table(b)
        has_fn = any(_CIPHER_RE.search(n) for n in b.elf.symbols)
        if addr is None and not has_fn:
            return 0, "no cipher table / decode function"
        if addr is not None:
            return 45, f"substitution table via {how}"
        return 30, "decode-like function present but no table located"

    def run(self, ctx, io):
        try:
            io.close()
        except Exception:
            pass
        b = ctx.binary
        addr, how = self._table(b)
        if addr is None:
            report.warn("subcipher: could not locate a substitution table")
            return None

        read, in_mapped, _ = _readers(b)
        mapping = reconstruct_table(read, in_mapped, addr)
        if not mapping:
            report.warn(f"subcipher: table at {hex(addr)} reconstructed empty")
            return None
        report.ok(f"reconstructed {len(mapping)} entries ({how})")

        # ---- suggest what cipher this is ----
        headline, lines = classify(mapping)
        report.step("Cipher suggestion:")
        report.info("  " + headline)
        for l in lines:
            report.info("  - " + l)
        inv = invert(mapping)
        sample = list(inv.items())[:_SAMPLE]
        report.info("  table: " + "  ".join(
            f"{c.decode('latin-1')}={t.decode('utf-8','replace')}"
            for c, t in sample) + (" ..." if len(inv) > _SAMPLE else ""))

        # ---- write the full mapping out for manual work ----
        mp = os.path.abspath(b.path) + ".cipher_map.txt"
        try:
            with open(mp, "w", encoding="utf-8") as fh:
                for c in sorted(inv, key=lambda x: x[0]):
                    fh.write(f"{chr(c[0])}\t{inv[c].decode('utf-8','replace')}\n")
            report.ok(f"full mapping written to {mp}")
        except Exception as e:
            report.warn(f"could not write mapping file: {e}")

        cipher_in = getattr(ctx.args, "cipher_input", None)
        if not cipher_in:
            report.warn("This binary is a decoder with no embedded flag. "
                        "Pass the challenge ciphertext to decode it:")
            report.warn(f"  python3 autoscram.py {b.path} --cipher-input '<tokens>'")
            return "CIPHER_TABLE_READY"          # clean stop, not a failure

        # ---- decode the provided ciphertext ----
        raw = cipher_in.encode() if isinstance(cipher_in, str) else cipher_in
        plain = decode(raw, mapping)
        if not plain:
            report.warn("nothing decoded; is the ciphertext in the right "
                        "token alphabet? (see the mapping file)")
            return None
        text = plain.decode(errors="replace")
        report.ok(f"decoded: {text}")

        mo = re.search(ctx.flag_re, text)
        if mo:
            report.ok(f"FLAG: {mo.group(0)}")
            return mo.group(0)

        # not a flag yet -> maybe another encoding layer; let magic suggest it
        report.step("Decoded text isn't a flag; trying common encodings on it...")
        for sc, chain, out in magic(plain, depth=2, top=5):
            if FLAG_RE.search(out):
                flag = FLAG_RE.search(out).group(0).decode(errors="replace")
                report.ok(f"FLAG via {' -> '.join(chain)}: {flag}")
                return flag
        report.info("No flag after extra decoding; the decoded text is above.")
        return text
