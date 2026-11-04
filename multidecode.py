#!/usr/bin/env python3
"""multidecode.py - try the common CTF encodings/ciphers on a blob and rank
what decodes to something sensible (ideally a flag).

Usage:
  python3 multidecode.py "U2FsdGVkX1..."         # decode an argument
  echo "0100011001..." | python3 multidecode.py  # or read stdin
  python3 multidecode.py --depth 3 "..."         # chain up to 3 layers
"""
import argparse
import sys

from autoscram.magic import magic, FLAG_RE


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data", nargs="?", help="ciphertext (else read stdin)")
    ap.add_argument("--depth", type=int, default=2, help="max chained layers")
    ap.add_argument("--top", type=int, default=8, help="how many results to show")
    args = ap.parse_args()

    raw = args.data.encode() if args.data else sys.stdin.buffer.read().strip()
    if not raw:
        ap.error("no input")

    results = magic(raw, depth=args.depth, top=args.top)
    if not results:
        print("[-] nothing decoded")
        return

    print(f"[*] top {len(results)} candidates (best first):\n")
    for sc, chain, out in results:
        txt = out.decode("latin-1")
        shown = txt if len(txt) <= 80 else txt[:77] + "..."
        tag = "  <-- FLAG" if FLAG_RE.search(out) else ""
        print(f"  score={sc:<5} via {' -> '.join(chain):<28} {shown!r}{tag}")
    best = results[0]
    print(f"\n[+] suggested: {' -> '.join(best[1])}")
    m = FLAG_RE.search(best[2])
    if m:
        print(f"[+] FLAG: {m.group(0).decode(errors='replace')}")


if __name__ == "__main__":
    main()
