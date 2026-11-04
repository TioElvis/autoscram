"""magic: try the most common CTF encodings/ciphers on a blob and rank the
results, so you can see what decodes to something sensible (ideally a flag).

Used by the `magic-decode` strategy and by the standalone `multidecode.py`.
It applies each decoder (and chains a couple of levels deep), scores every
result by printability / flag-shape / common words, and returns the best.
"""
import base64
import binascii
import codecs
import re
import string
import urllib.parse

FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,24}\{[^}\n]{1,120}\}")
_COMMON = (b"flag", b"ctf", b"the", b"and", b"you", b"key", b"secret", b"http",
           b"congrat", b"well", b"done", b"pass", b"admin", b"user", b"code")
_PRINT = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")

_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


# ---------------------------------------------------------------- decoders
def _printable(b):
    if not b:
        return False
    return sum(c in _PRINT for c in b) / len(b) > 0.85


def d_base64(b):
    s = b.strip()
    s += b"=" * (-len(s) % 4)
    return base64.b64decode(s, validate=False)


def d_base64url(b):
    s = b.strip().replace(b"-", b"+").replace(b"_", b"/")
    s += b"=" * (-len(s) % 4)
    return base64.b64decode(s, validate=False)


def d_base32(b):
    s = b.strip().upper()
    s += b"=" * (-len(s) % 8)
    return base64.b32decode(s)


def d_base85(b):
    return base64.b85decode(b.strip())


def d_ascii85(b):
    return base64.a85decode(b.strip())


def d_hex(b):
    s = re.sub(rb"[^0-9a-fA-F]", b"", b)
    if len(s) % 2:
        return None
    return binascii.unhexlify(s)


def d_decimal(b):
    nums = re.findall(rb"\d{1,3}", b)
    if not nums:
        return None
    vals = [int(n) for n in nums]
    if any(v > 255 for v in vals):
        return None
    return bytes(vals)


def d_binary(b):
    bits = re.sub(rb"[^01]", b"", b)
    if len(bits) < 8 or len(bits) % 8:
        return None
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def d_url(b):
    return urllib.parse.unquote_to_bytes(b)


def d_rot13(b):
    return codecs.encode(b.decode("latin-1"), "rot13").encode("latin-1")


def d_reverse(b):
    return b[::-1]


def d_atbash(b):
    out = bytearray()
    for c in b:
        if 65 <= c <= 90:
            out.append(90 - (c - 65))
        elif 97 <= c <= 122:
            out.append(122 - (c - 97))
        else:
            out.append(c)
    return bytes(out)


def d_rot47(b):
    out = bytearray()
    for c in b:
        out.append(33 + (c - 33 + 47) % 94 if 33 <= c <= 126 else c)
    return bytes(out)


def d_morse(b):
    txt = b.decode("latin-1").strip()
    if not set(txt) <= set(".-/ \t\n"):
        return None
    words = re.split(r"\s*/\s*|\s{2,}", txt)
    out = []
    for w in words:
        out.append("".join(_MORSE.get(sym, "") for sym in w.split()))
    return (" ".join(out)).encode()


def _caesar(b, k):
    out = bytearray()
    for c in b:
        if 65 <= c <= 90:
            out.append((c - 65 + k) % 26 + 65)
        elif 97 <= c <= 122:
            out.append((c - 97 + k) % 26 + 97)
        else:
            out.append(c)
    return bytes(out)


def _xor1(b, k):
    return bytes(c ^ k for c in b)


# name -> function, run in this order
DECODERS = [
    ("base64", d_base64), ("base64url", d_base64url), ("base32", d_base32),
    ("base85", d_base85), ("ascii85", d_ascii85), ("hex", d_hex),
    ("decimal", d_decimal), ("binary", d_binary), ("url", d_url),
    ("rot13", d_rot13), ("rot47", d_rot47), ("atbash", d_atbash),
    ("reverse", d_reverse), ("morse", d_morse),
]


# ---------------------------------------------------------------- scoring
def score(b):
    if not b:
        return -1
    s = 0
    if FLAG_RE.search(b):
        s += 1000
    if _printable(b):
        s += 40
        low = b.lower()
        s += 8 * sum(w in low for w in _COMMON)
    else:
        s -= 50
    return s


def _try_all(b):
    """One level: yield (name, result) for every decoder that produced bytes."""
    for name, fn in DECODERS:
        try:
            r = fn(b)
        except Exception:
            r = None
        if r:
            yield name, r
    # brute families
    for k in range(1, 26):
        try:
            yield f"caesar+{k}", _caesar(b, k)
        except Exception:
            pass
    if len(b) <= 4096:
        for k in range(1, 256):
            r = _xor1(b, k)
            if _printable(r):
                yield f"xor:{k:#04x}", r


def magic(data, depth=2, top=8):
    """Return ranked [(score, chain, result_bytes)] over up to `depth` levels."""
    if isinstance(data, str):
        data = data.encode()
    seen = {data}
    results = []
    frontier = [([], data)]
    for _ in range(depth):
        nxt = []
        for chain, blob in frontier:
            for name, r in _try_all(blob):
                if r in seen:
                    continue
                seen.add(r)
                ch = chain + [name]
                sc = score(r)
                results.append((sc, ch, r))
                if sc < 900:                    # keep chaining only promising-ish
                    nxt.append((ch, r))
        # keep the best branches to chain further
        nxt.sort(key=lambda x: score(x[1]), reverse=True)
        frontier = nxt[:12]
    results.sort(key=lambda x: x[0], reverse=True)
    # de-dup identical results, keep best chain
    out, taken = [], set()
    for sc, ch, r in results:
        if r in taken:
            continue
        taken.add(r)
        out.append((sc, ch, r))
        if len(out) >= top:
            break
    return out
