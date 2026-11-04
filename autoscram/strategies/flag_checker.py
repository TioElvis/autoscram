"""Static flag-checker solver (reverse-engineering, not memory corruption).

Handles binaries (C or Rust) that read an input and verify it against a
constant, typically:   transform(input[i], key[i % K]) == target[i]
where transform is XOR / ADD / SUB, or a direct byte comparison.

It locates the checker's constant arrays in read-only data, reads them, derives
the input for each candidate operation, and VERIFIES by running the binary --
so it doesn't need to perfectly decode the transform, it just tries the few
common ones and keeps the one the binary accepts. The accepted input *is* the
flag.
"""
import os
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from pwn import process

from .base import Strategy
from .. import report
from ..analysis import find_main

_CHECKER_RE = re.compile(r"check|flag|verif|valid|ticket|solve|secret|compare",
                         re.I)
_FAIL_WORDS = (b"error", b"wrong", b"invalid", b"denied", b"fail", b"garbage",
               b"mismatch", b"nope", b"incorrect", b"try again", b"no ticket",
               b"expected", b"not ")
_WIN_WORDS = (b"success", b"correct", b"congrat", b"accepted", b"well done",
              b"welcome", b"granted", b"approved", b"unlock", b"access granted")


def _ro_data(binary, addr):
    """True if addr is in a non-writable loadable segment (rodata-ish)."""
    try:
        for seg in binary.elf.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue
            start = seg.header.p_vaddr
            if start <= addr < start + seg.header.p_memsz:
                return not (seg.header.p_flags & 2)      # not PF_W
    except Exception:
        pass
    return False


def scan_consts(binary, start, md):
    """Return (arrays[(addr,size)], lengths[int]) referenced in a function."""
    try:
        code = binary.elf.read(start, 0x500)
    except Exception:
        return [], []
    arrays, lengths = [], []
    pending = None
    for insn in md.disasm(code, start):
        ops = insn.operands
        mn = insn.mnemonic
        if mn == "lea" and len(ops) == 2 and ops[1].type == X86_OP_MEM \
                and ops[1].mem.base and insn.reg_name(ops[1].mem.base) == "rip":
            addr = insn.address + insn.size + ops[1].mem.disp
            pending = addr if _ro_data(binary, addr) else None
        elif mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_IMM \
                and insn.reg_name(ops[0].reg) in ("esi", "edx", "ecx") \
                and 0 < ops[1].imm < 0x1000:
            if pending is not None:
                arrays.append((pending, ops[1].imm))
                pending = None
        elif mn == "cmp" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_IMM \
                and insn.reg_name(ops[0].reg) in ("rax", "rdx", "rcx") \
                and 0 < ops[1].imm < 0x1000:
            lengths.append(ops[1].imm)
        if mn == "ret":
            break
    return arrays, lengths


def _checker_funcs(binary):
    # search ALL symbols (incl. mangled Rust/C++ names starting with _Z/_R)
    funcs = [a for n, a in binary.elf.symbols.items()
             if _CHECKER_RE.search(n) and binary.in_executable(a)
             and "@" not in n and not n.startswith("plt.")]
    if funcs:
        return list(dict.fromkeys(funcs))
    # stripped / no match: main and the functions it calls
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    main = find_main(binary)
    if main is None:
        return []
    out = {main}
    try:
        code = binary.elf.read(main, 0x600)
        for insn in md.disasm(code, main):
            if insn.mnemonic == "call" and insn.operands \
                    and insn.operands[0].type == X86_OP_IMM:
                t = insn.operands[0].imm
                if binary.in_executable(t):
                    out.add(t)
            if insn.mnemonic == "ret":
                break
    except Exception:
        pass
    return list(out)


def _derive(op, target, key):
    n = len(target)
    if op == "direct":
        return bytes(target)
    if key is None:
        return None
    k = len(key)
    if op == "add":        # checker: (in + key) == target  -> in = target - key
        return bytes((target[i] - key[i % k]) & 0xff for i in range(n))
    if op == "sub":        # checker: (in - key) == target  -> in = target + key
        return bytes((target[i] + key[i % k]) & 0xff for i in range(n))
    if op == "xor":
        return bytes((target[i] ^ key[i % k]) for i in range(n))
    return None


def _printable(b):
    return b and all(32 <= c < 127 for c in b)


class FlagChecker(Strategy):
    name = "flag-checker"
    desc = "statically solve a constant flag check (XOR/ADD/SUB/direct)"
    verifiable = False          # solved statically + self-verified here

    def _collect(self, ctx):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        arrays, lengths = [], []
        for fa in _checker_funcs(ctx.binary):
            a, l = scan_consts(ctx.binary, fa, md)
            arrays += a
            lengths += l
        # de-dup
        arrays = list(dict.fromkeys(arrays))
        return arrays, sorted(set(lengths))

    def detect(self, ctx):
        # only interesting when no memory-corruption input was found
        if ctx.analysis.primary_input:
            return 0, "has a corruption primitive; not a static checker"
        arrays, lengths = self._collect(ctx)
        if not arrays:
            return 0, "no constant arrays found in checker functions"
        return 60, f"{len(arrays)} constant array(s), lengths {lengths or '?'}"

    def _runbin(self, path, data):
        try:
            io = process(path)
            io.sendline(data)
            out = io.recvall(timeout=4)
            io.close()
            return out
        except Exception:
            return b""

    def _verify(self, path, cand, baseline):
        if not _printable(cand):
            return False, b""
        out = self._runbin(path, cand)
        low = out.lower()
        win = any(w in low for w in _WIN_WORDS)
        fail = any(w in low for w in _FAIL_WORDS)
        # a success word wins outright (e.g. "...Successful. 0 Errors."); else
        # accept only if the response changed from a wrong input and isn't a
        # failure message.
        accept = win or (out != baseline and not fail)
        return accept, out

    def run(self, ctx, io):
        try:
            io.close()               # this strategy solves statically
        except Exception:
            pass
        arrays, lengths = self._collect(ctx)
        if not arrays:
            report.warn("flag-checker: no constant arrays")
            return None

        report.step(f"flag-checker: arrays={[(hex(a),s) for a,s in arrays]} "
                    f"lengths={lengths}")

        # target = array whose size matches a length check (else the largest)
        flag_len = lengths[-1] if lengths else max(s for _, s in arrays)
        targets = [(a, s) for a, s in arrays if s == flag_len] or \
                  sorted(arrays, key=lambda x: -x[1])[:1]
        keys = [(a, s) for a, s in arrays if s != flag_len]

        read = ctx.binary.read_cstr  # not used; read raw bytes instead
        def rd(a, s):
            try:
                return ctx.binary.elf.read(a, s)
            except Exception:
                return b""

        baseline = self._runbin(ctx.binary.path, b"A" * flag_len)

        tried = 0
        for (ta, ts) in targets:
            target = rd(ta, ts)
            if not target:
                continue
            key_opts = [None] + [rd(ka, ks) for ka, ks in keys]
            for key in key_opts:
                for op in ("add", "sub", "xor", "direct"):
                    cand = _derive(op, target, key)
                    if cand is None:
                        continue
                    tried += 1
                    ok, out = self._verify(ctx.binary.path, cand, baseline)
                    if ok:
                        report.ok(f"solved with op={op} "
                                  f"key={'yes' if key else 'none'}")
                        # prefer a flag{...} match in the output, else the input
                        out_s = out.decode(errors="replace")
                        cand_s = cand.decode(errors="replace")
                        m = re.search(ctx.flag_re, out_s) or \
                            re.search(ctx.flag_re, cand_s)
                        flag = m.group(0) if m else cand_s
                        report.ok(f"FLAG: {flag}")
                        return flag
        report.warn(f"flag-checker: tried {tried} combos, none accepted")
        return None
