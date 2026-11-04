# AUTOSCRAM

Modular **auto-pwn framework** for x86-64 Linux CTF pwnables. Give it a binary;
it triages the protections, **statically analyzes `main` to detect the bug
class**, builds the exploit, **verifies it locally**, and fires it at a local
process or a remote `host:port`.

```
python3 autoscram.py ./challenge               # analyze + exploit locally
python3 autoscram.py ./challenge --remote host:1337
```

> Educational / CTF use only. Run it only against targets you're allowed to
> test (your own machines or a CTF you're registered for).

---

## What it does automatically

1. **Triage** — PIE / NX / canary / RELRO, imported functions, `/bin/sh`.
2. **Static analysis** (capstone) of `main` and the functions it calls — tracks
   `rbp`-relative addresses to find:
   - the vulnerable input (`scanf("%s")`, `gets`, `read(0, buf, n)`) and **where
     it writes** plus **how many bytes**,
   - every `strcmp(buf+off, "constant")` and the offset it guards,
   - `printf(buf)` **format-string** leak primitives,
   - the **stack-canary** slot,
   - the block / function that prints `getenv("FLAG")` (a ret2win target).
3. **Strategy ranking** — each strategy scores itself on the analysis; the best
   is chosen (you can override).
4. **Offset discovery** — De Bruijn pattern + corefile (`fault_addr`), no manual
   `±8`.
5. **Local self-test** — runs the payload on the local copy with a sentinel
   `FLAG` before firing at the remote.
6. **Exploit** — captures the flag, or drops you into a shell for `system`
   strategies.

## Strategies

| Strategy | When it wins | How |
|----------|--------------|-----|
| `data-overflow` | an unbounded read sits **before** the variables compared by `strcmp` | one `scanf`-safe token places each required constant at its offset (NUL-separated) |
| `fmt-leak-ret2win` | a user buffer is passed to `printf` as its format **and** there's an overflow past a **stack canary** | leak the canary with positional `%N$p`, then overflow with the canary in place and jump to a win function |
| `ret2win` | a win function / flag block exists and the binary is non-PIE | overflow RET → jump to the flag-printing code |
| `ret2system` | binary imports `system` and holds `/bin/sh` (non-PIE) | pwntools ROP `system("/bin/sh")` → shell |
| `flag-checker` | no memory bug — the binary just **verifies** your input against a constant (C or **Rust**) | reads the checker's constant arrays, derives the input for XOR / ADD / SUB / direct compare, and **verifies by running the binary** |
| `cipher-fmt` | a substitution decoder whose decoded output is passed to **`printf` as its format** (e.g. the emoji cipher's remote) | reconstructs the table, **encodes a `%p`/`%s` format-string leak as tokens**, fires it at the local/remote target and reads the flag out of the leak — one command, no manual payload |
| `subcipher` | the binary is a **substitution-cipher tool** (e.g. an emoji cipher) that maps plaintext bytes to tokens and has no embedded flag | reconstructs the table (by symbol, or by **scanning data** when stripped), **suggests what cipher it is**, writes the full mapping to `<bin>.cipher_map.txt`, and decodes the ciphertext passed via `--cipher-input` (chaining `magic-decode` if the result is still encoded) |
| `magic-decode` | you pass `--cipher-input` and the blob is a **standard encoding/cipher** (base64, hex, rot13, xor, morse, …) | tries the common decoders (chained a few layers), ranks by flag-shape / readability, and suggests the chain |

The analysis is what makes the choice correct:
- if a gating `strcmp` is **behind** the input buffer (a forward overflow can't
  reach it), `data-overflow` scores low and `ret2win` takes over;
- if a **stack canary** guards the RET but a `printf(buf)` format string exists,
  `fmt-leak-ret2win` wins and defeats the canary with a runtime leak.

Analysis follows `main` **into the functions it calls**, so a vulnerability in a
helper (e.g. `diagnostic_mode`) is found, and locates `main` from `_start` even
on **stripped** binaries.

### Worked examples

```
# who_are_you  (PIE, strcmp(buf+0,"root") & strcmp(buf+0x64,"root"))
$ python3 autoscram.py ./who_are_you
[*] strcmp(rbp-0xd0, b'root') ; strcmp(rbp-0x6c, b'root')
[*] data-overflow score=90 -> place 0x0=b'root', 0x64=b'root'
[+] FLAG: FLAG{...}

# reactor_override  (non-PIE, one check is BEHIND the input -> ret2win)
$ python3 autoscram.py ./reactor_override
[*] data-overflow score=15 (1 check behind the input buffer)
[*] ret2win score=70 -> flag block @ 0x401261 ; RET offset = 116
[+] FLAG: FLAG{...}

# odb_diagnostic  (canary + printf(buf) format string + read() overflow)
$ python3 autoscram.py ./odb_diagnostic
[*] input: read -> rbp-0x50, 256B (overflow) ; printf(rbp-0x90) FORMAT STRING
[*] canary stored at rbp-0x8 ; win function bypass_immobilizer @ 0x401196
[*] fmt-leak-ret2win score=88
[+] leaked canary = 0x....00  -> overflow + ret2win
[+] FLAG: FLAG{...}

# ferris_wheel_2  (Rust RE: check_flag does (input+key)%256 == target)
$ python3 autoscram.py ./ferris_wheel_2
[*] flag-checker score=60  7 constant array(s), lengths [29]
[+] solved with op=add key=yes
[+] FLAG: flag{...}

# emoji_cipher  (substitution-cipher tool, no embedded flag)
$ python3 autoscram.py ./emoji_cipher --cipher-input "🐸🦙🐜🦒📦..."
[+] reconstructed substitution table: 94 entries
[+] FLAG: flag{...}
```

## Standalone multi-decoder

For plain "decode this" challenges you don't even need a binary — point the
multi-decoder at the blob and it tries the common encodings/ciphers, ranks what
decodes to something sensible, and suggests the chain:

```bash
python3 multidecode.py "ZmxhZ3tiNHNlNjRfdzFufQ=="     # base64 -> flag{...}
echo "01100110 01101100 ..." | python3 multidecode.py # or read stdin
python3 multidecode.py --depth 3 "..."                # chain up to 3 layers
```

Covers: base64/64url/32/85/ascii85, hex, decimal, binary, URL, rot13, rot47,
atbash, reverse, caesar (all shifts), single-byte xor (all keys), morse — and
chains of them. The same engine backs the `magic-decode` strategy.

## Install

```bash
pip install -r requirements.txt     # pwntools + capstone, Python 3
```

Core dumps are enabled automatically (via `setrlimit`), so you don't need
`ulimit -c unlimited`.

## Options

| Option | Description |
|--------|-------------|
| `binary` | local target binary (required) |
| `--remote HOST:PORT` | exploit a remote service |
| `--local` | force local, no prompt |
| `--only NAME` | force a strategy: `data-overflow` \| `ret2win` \| `ret2system` |
| `--target 0xADDR` | ret2win: explicit win address |
| `--offset N` | override the auto RET offset |
| `--align` | ret2win: add a `ret` gadget for 16-byte stack alignment |
| `--flag-format RE` | regex to recognize the flag (default `xxx{...}`) |
| `--cipher-input TOKENS` | subcipher: the challenge ciphertext to decode |
| `--no-verify` | skip the local self-test |
| `--yes` | take the top-ranked strategy without asking |

## Project layout

```
autoscram.py              # entrypoint
multidecode.py            # standalone multi-decoder CLI
autoscram/
├── cli.py                # orchestrator: triage -> rank -> verify -> exploit
├── binary.py             # ELF wrapper: protections, strings, gadgets
├── analysis.py           # capstone static analysis of main()
├── offset.py             # cyclic + corefile RET-offset finder
├── comms.py              # local/remote I/O, flag detection, self-test
├── magic.py              # multi-decoder engine (encodings/ciphers + ranking)
├── cipher.py             # substitution-table rebuild / classify / decode (no pwntools)
├── context.py            # shared context passed to strategies
├── report.py             # logging / banner
└── strategies/
    ├── base.py           # Strategy interface (detect / build / run)
    ├── data_overflow.py  # overwrite adjacent vars to pass strcmp
    ├── fmt_leak.py       # format-string canary leak + overflow + ret2win
    ├── flag_checker.py   # static solve of a constant flag check (C / Rust)
    ├── subcipher.py      # reconstruct a substitution cipher + decode ciphertext
    ├── magic_decode.py   # try common encodings/ciphers on --cipher-input
    ├── ret2win.py        # jump to win function / flag block
    └── ret2system.py     # ROP system('/bin/sh')
```

Strategies are either **single-shot** (implement `build()`) or **multi-stage**
(override `run(ctx, io)` to drive the whole conversation — e.g. leak then
overflow). The orchestrator self-tests each one by running it end-to-end against
a local copy with a sentinel `FLAG` before firing at the real target.

## Adding a strategy

Subclass `Strategy`, implement `detect(ctx) -> (score, reason)` and
`build(ctx) -> (payload, interactive, note)`, and add it to
`strategies/ALL`. The context gives you `ctx.binary`, `ctx.analysis`
(inputs, checks, win funcs, flag block) and `ctx.ret_offset()`.

## Scope / limits

- Handles **non-PIE ret2win / ret2system**, **forward-overflow auth bypass**,
  **stack-canary bypass via a format-string leak**, and **static flag-checkers**
  (C or Rust) that compare your input to a constant.
- Works on **stripped** binaries and vulnerabilities inside helper functions.
- **PIE** memory-corruption still needs a code/base leak — AUTOSCRAM flags this
  but does not yet auto-leak a PIE base (next strategy to add). PIE does **not**
  block the `flag-checker` strategy, which is purely static.
- Heap and other bug classes are out of scope (add a strategy).

## License

MIT
