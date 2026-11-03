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
2. **Static analysis of `main`** (capstone) — tracks `rbp`-relative addresses to
   find:
   - the vulnerable input (`scanf("%s")`, `gets`) and **where it writes**,
   - every `strcmp(buf+off, "constant")` and the offset it guards,
   - the block that prints `getenv("FLAG")` (a ret2win target).
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
| `ret2win` | a win function / flag block exists and the binary is non-PIE | overflow RET → jump to the flag-printing code |
| `ret2system` | binary imports `system` and holds `/bin/sh` (non-PIE) | pwntools ROP `system("/bin/sh")` → shell |

The analysis is what makes the choice correct: if a gating `strcmp` is **behind**
the input buffer (a forward overflow can't reach it), `data-overflow` scores low
and `ret2win` takes over — automatically.

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
```

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
| `--no-verify` | skip the local self-test |
| `--yes` | take the top-ranked strategy without asking |

## Project layout

```
autoscram.py              # entrypoint
autoscram/
├── cli.py                # orchestrator: triage -> rank -> verify -> exploit
├── binary.py             # ELF wrapper: protections, strings, gadgets
├── analysis.py           # capstone static analysis of main()
├── offset.py             # cyclic + corefile RET-offset finder
├── comms.py              # local/remote I/O, flag detection, self-test
├── context.py            # shared context passed to strategies
├── report.py             # logging / banner
└── strategies/
    ├── base.py           # Strategy interface (detect/build)
    ├── data_overflow.py  # overwrite adjacent vars to pass strcmp
    ├── ret2win.py        # jump to win function / flag block
    └── ret2system.py     # ROP system('/bin/sh')
```

## Adding a strategy

Subclass `Strategy`, implement `detect(ctx) -> (score, reason)` and
`build(ctx) -> (payload, interactive, note)`, and add it to
`strategies/ALL`. The context gives you `ctx.binary`, `ctx.analysis`
(inputs, checks, win funcs, flag block) and `ctx.ret_offset()`.

## Scope / limits

- Handles **non-PIE ret2win / ret2system** and **forward-overflow auth bypass**.
- **PIE** ret2win/ret2system need a runtime leak — AUTOSCRAM flags this but does
  not yet auto-leak. **Canary** is detected and flagged, not bypassed.
- Format-string, heap, and other bug classes are out of scope (add a strategy).

## License

MIT
