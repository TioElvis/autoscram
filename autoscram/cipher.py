"""Substitution-cipher primitives, free of pwntools so they can be unit-tested.

A class of CTF binaries ships a *decoder tool* rather than a flag: a table maps
each plaintext byte to a token (an emoji, a word, a glyph) and the program turns
tokens back into text. This module reconstructs that table from raw memory,
decodes a token stream, and -- the part the `subcipher` strategy surfaces to the
user -- classifies the table so AUTOSCRAM can *suggest what cipher it is*.

Everything here takes plain callables (`read(addr, n) -> bytes`,
`in_mapped(addr) -> bool`) instead of a pwntools ELF, so the binary wiring lives
in the strategy and the logic stays testable on its own.
"""
import string

PRINTABLE = set(range(0x21, 0x7f))
_LETTERS = set(range(0x41, 0x5b)) | set(range(0x61, 0x7b))
_ALNUM = _LETTERS | set(range(0x30, 0x3a))


# ---------------------------------------------------------------- reconstruct
def reconstruct_table(read, in_mapped, table_addr,
                      stride=16, char_off=0, ptr_off=8, maxn=512):
    """Rebuild {token_bytes: plaintext_byte} from an array of {char, ptr} rows.

    `read(addr, n)` returns bytes (possibly short/empty), `in_mapped(addr)` says
    whether an address is inside a loaded segment. Stops at the first row whose
    pointer field isn't a real pointer into mapped memory.
    """
    mapping = {}
    for i in range(maxn):
        ent = table_addr + i * stride
        if not in_mapped(ent + ptr_off):
            break
        ch = read(ent + char_off, 1)
        raw = read(ent + ptr_off, 8)
        if len(raw) < 8:
            break
        ptr = int.from_bytes(raw, "little")
        if not ch or ch == b"\x00" or ptr == 0 or not in_mapped(ptr):
            if i > 10:          # a few empty leading slots are tolerated
                break
            continue
        tok = read(ptr, 32).split(b"\x00", 1)[0]
        if not tok:
            break
        mapping.setdefault(tok, ch)
    return mapping


def decode(data, mapping, strict=False):
    """Turn a token stream into plaintext using the longest matching token.

    Unmatched bytes are skipped (they're usually separators). With strict=True a
    byte that matches no token is kept verbatim instead, which helps when the
    ciphertext mixes plain text and tokens.
    """
    items = sorted(mapping.items(), key=lambda kv: -len(kv[0]))
    out = bytearray()
    i = 0
    while i < len(data):
        for tok, ch in items:
            if tok and data[i:i + len(tok)] == tok:
                out += ch
                i += len(tok)
                break
        else:
            if strict:
                out.append(data[i])
            i += 1
    return bytes(out)


def invert(mapping):
    """plaintext_byte -> token, for encoding / showing the table by letter."""
    out = {}
    for tok, ch in mapping.items():
        out.setdefault(ch, tok)
    return out


# ---------------------------------------------------------------- classify
def _token_kind(tokens):
    if all(len(t) == 1 and t[0] < 0x80 for t in tokens):
        return "single ASCII characters"
    if any(b >= 0x80 for t in tokens for b in t):
        # crude emoji vs. other-unicode split by the common emoji planes
        joined = b"".join(tokens)
        if b"\xf0\x9f" in joined or b"\xe2" in joined:
            return "emoji / Unicode symbols"
        return "multi-byte Unicode tokens"
    if all(t.isalnum() for t in tokens) and any(len(t) > 1 for t in tokens):
        return "words / alphanumeric tokens"
    return "multi-byte tokens"


def _charset_name(chars):
    s = set(chars)
    if s == PRINTABLE:
        return "the full printable ASCII set (0x21-0x7e)"
    if s <= _LETTERS:
        return "ASCII letters"
    if s <= _ALNUM:
        return "ASCII letters and digits"
    if s <= PRINTABLE:
        return f"a subset of printable ASCII ({len(s)} chars)"
    return f"{len(s)} byte values"


def classify(mapping):
    """Return (headline, [suggestion lines]) describing the cipher."""
    if not mapping:
        return "no table reconstructed", []
    tokens = list(mapping.keys())
    plain = [c[0] for c in mapping.values()]
    kind = _token_kind(tokens)
    charset = _charset_name(plain)

    lines = [
        f"monoalphabetic substitution cipher: {len(mapping)} tokens "
        f"<-> {charset}",
        f"tokens look like {kind}",
    ]

    # single-char tokens over letters => a classic cipher; magic can name it
    if kind == "single ASCII characters" and set(plain) <= _LETTERS:
        lines.append("both sides are letters: likely Caesar / Atbash / keyword "
                     "-- try `multidecode.py` on the ciphertext too")

    # is the plaintext side just sequential (table index == rank)? then the
    # token order itself is the alphabet and position encodes the character.
    ordered = "".join(chr(c) for c in plain)
    if ordered == string.ascii_uppercase + string.ascii_lowercase:
        lines.append("plaintext side is A-Z a-z in order: the Nth token is "
                     "simply the Nth letter")

    dup = len(tokens) - len(set(tokens))
    if dup:
        lines.append(f"warning: {dup} duplicate token(s) -- decode may be "
                     "ambiguous")
    return lines[0], lines[1:]


# ---------------------------------------------------------------- find table
def find_table_by_scan(read, in_mapped, in_rodata, sections,
                       stride=16, char_off=0, ptr_off=8, min_run=8):
    """Locate a {char, rodata-ptr} table without a symbol (stripped binaries).

    `sections` is a list of (addr, size) data regions to scan. A row qualifies
    when its pointer field points into read-only data (where the token strings
    live) and its char field is a printable byte. Returns the start address of
    the longest qualifying run, or None.
    """
    best_addr, best_len = None, 0
    for base, size in sections:
        addr = base
        end = base + size
        while addr + stride <= end:
            run_start, run = addr, 0
            while addr + stride <= end:
                ch = read(addr + char_off, 1)
                raw = read(addr + ptr_off, 8)
                if len(raw) < 8:
                    break
                ptr = int.from_bytes(raw, "little")
                if ch and ch[0] in PRINTABLE and ptr and in_rodata(ptr):
                    tok = read(ptr, 4)
                    if tok and tok[0] != 0:
                        run += 1
                        addr += stride
                        continue
                break
            if run > best_len:
                best_addr, best_len = run_start, run
            addr = run_start + stride if run == 0 else addr
    return best_addr if best_len >= min_run else None
