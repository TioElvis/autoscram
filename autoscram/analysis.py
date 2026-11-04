"""Static analysis of `main`: input sites, strcmp checks, format-string leaks,
the stack-canary slot, and the flag block.

Walks main linearly with capstone, tracking rbp-relative addresses and
immediate register values, to answer: where does input land and how big is it,
which fixed strings are compared against which offsets, is a user buffer passed
to printf as its format (a leak primitive), and where is the canary stored.
"""
from dataclasses import dataclass, field

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

from . import report

WIN_KEYWORDS = ("win", "flag", "shell", "backdoor", "secret", "giveshell",
                "give_shell", "get_shell", "getshell", "print_flag", "get_flag",
                "cat_flag", "readflag", "admin", "magic", "success", "pwn",
                "bypass", "unlock", "immobil", "auth", "decrypt", "reveal",
                "grant", "override", "engine")

# 32-bit -> 64-bit register canonicalization (so `mov edx, N` tracks as rdx)
_CANON = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
          "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp"}


def _canon(name):
    return _CANON.get(name, name)


@dataclass
class InputSite:
    func: str            # scanf / gets / read
    off: int             # rbp-relative offset where input lands
    unbounded: bool      # True if it can overflow past its buffer
    size: int = None     # byte count for read()


@dataclass
class Check:
    off: int
    const: bytes


@dataclass
class Analysis:
    inputs: list = field(default_factory=list)
    checks: list = field(default_factory=list)
    fmt_leaks: list = field(default_factory=list)   # rbp offsets used as printf fmt
    getenv_flag: bool = False
    flag_block: int = None
    win_funcs: list = field(default_factory=list)
    canary_off: int = None                          # rbp offset of the canary
    notes: list = field(default_factory=list)

    @property
    def primary_input(self):
        return self.inputs[0] if self.inputs else None

    def overflow_input(self):
        """The input most able to smash the return address."""
        cand = [i for i in self.inputs if i.unbounded]
        if not cand:
            return None
        # biggest reach wins (read size, else assume large for scanf/gets)
        return max(cand, key=lambda i: i.size or 1 << 20)


def _name_map(elf):
    m = {}
    for n, a in elf.plt.items():
        m[a] = n
    for n, a in elf.symbols.items():
        m.setdefault(a, n)
    return m


def _norm(name):
    if name in ("__isoc23_scanf", "scanf", "__isoc99_scanf"):
        return "scanf"
    return name


def find_main(binary):
    """Return main's address, even on stripped binaries (via _start's RDI)."""
    elf = binary.elf
    if "main" in elf.symbols:
        return elf.symbols["main"]
    try:
        code = elf.read(elf.entry, 80)
    except Exception:
        return None
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    rdi = None
    for insn in md.disasm(code, elf.entry):
        ops = insn.operands
        if insn.mnemonic == "lea" and len(ops) == 2 \
                and ops[0].type == X86_OP_REG and insn.reg_name(ops[0].reg) == "rdi" \
                and ops[1].type == X86_OP_MEM and ops[1].mem.base \
                and insn.reg_name(ops[1].mem.base) == "rip":
            rdi = insn.address + insn.size + ops[1].mem.disp
        elif insn.mnemonic == "mov" and len(ops) == 2 \
                and ops[0].type == X86_OP_REG \
                and insn.reg_name(ops[0].reg) in ("rdi", "edi") \
                and ops[1].type == X86_OP_IMM:
            rdi = ops[1].imm
        elif insn.mnemonic == "call":
            break
    return rdi


def _scan(binary, start, md, names):
    """Linear scan of one function. Returns (partial Analysis, callee addrs)."""
    part = Analysis()
    callees = set()
    try:
        code = binary.elf.read(start, 0x900)
    except Exception:
        return part, callees

    regs = {}
    block_start = start
    pending_block = False

    def V(reg):
        return regs.get(_canon(reg))

    for insn in md.disasm(code, start):
        if pending_block:
            block_start = insn.address
            pending_block = False
        mn = insn.mnemonic
        ops = insn.operands

        if mn == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_MEM:
            dst = _canon(insn.reg_name(ops[0].reg))
            mem = ops[1].mem
            base = insn.reg_name(mem.base) if mem.base else None
            disp = mem.disp
            if base == "rbp":
                regs[dst] = ("rbp", disp)
            elif base == "rip":
                vaddr = insn.address + insn.size + disp
                regs[dst] = ("str", vaddr, binary.read_cstr(vaddr))
            elif base and V(base) and V(base)[0] == "rbp":
                regs[dst] = ("rbp", V(base)[1] + disp)
            else:
                regs[dst] = None

        elif mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG:
            dst = _canon(insn.reg_name(ops[0].reg))
            src = ops[1]
            if src.type == X86_OP_REG:
                regs[dst] = V(insn.reg_name(src.reg))
            elif src.type == X86_OP_IMM:
                regs[dst] = ("imm", src.imm)
            elif src.type == X86_OP_MEM and src.mem.segment != 0 \
                    and src.mem.disp == 0x28:
                regs[dst] = ("canary",)
            else:
                regs[dst] = None

        elif mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_MEM \
                and ops[1].type == X86_OP_REG:
            mem = ops[0].mem
            base = insn.reg_name(mem.base) if mem.base else None
            if base == "rbp" and V(insn.reg_name(ops[1].reg)) == ("canary",):
                part.canary_off = mem.disp

        elif mn == "add" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_IMM:
            dst = _canon(insn.reg_name(ops[0].reg))
            cur = V(dst)
            if cur and cur[0] == "rbp":
                regs[dst] = ("rbp", cur[1] + ops[1].imm)

        if mn.startswith("j") and mn != "jmp":
            pending_block = True

        if mn == "call" and ops and ops[0].type == X86_OP_IMM:
            target = ops[0].imm
            fname = _norm(names.get(target, ""))
            if fname == "" and binary.in_executable(target):
                callees.add(target)                 # local helper function
            rdi, rsi, rdx = V("rdi"), V("rsi"), V("rdx")

            if fname == "scanf":
                buf = rsi if (rsi and rsi[0] == "rbp") else None
                if buf:
                    unb = True
                    if rdi and rdi[0] == "str" and b"%" in rdi[2]:
                        unb = b"%s" in rdi[2]
                    part.inputs.append(InputSite("scanf", buf[1], unb))
            elif fname == "gets":
                buf = rdi if (rdi and rdi[0] == "rbp") else None
                if buf:
                    part.inputs.append(InputSite("gets", buf[1], True))
            elif fname == "read":
                buf = rsi if (rsi and rsi[0] == "rbp") else None
                size = rdx[1] if (rdx and rdx[0] == "imm") else None
                if buf:
                    reach = size is None or (buf[1] + size) > 8
                    part.inputs.append(InputSite("read", buf[1], reach, size))
            elif fname == "strcmp":
                buf = const = None
                for v in (rdi, rsi):
                    if v and v[0] == "rbp":
                        buf = v
                    elif v and v[0] == "str":
                        const = v
                if buf and const:
                    part.checks.append(Check(buf[1], const[2]))
            elif fname == "printf":
                if rdi and rdi[0] == "rbp":
                    part.fmt_leaks.append(rdi[1])
            elif fname == "getenv":
                if rdi and rdi[0] == "str" and rdi[2] == b"FLAG":
                    part.getenv_flag = True
                    part.flag_block = block_start

        if mn == "ret":
            break

    return part, callees


def analyze(binary):
    elf = binary.elf
    res = Analysis()

    for name, addr in binary.functions():
        low = name.lower()
        if any(k in low for k in WIN_KEYWORDS):
            res.win_funcs.append((name, addr))

    main = find_main(binary)
    if main is None:
        res.notes.append("could not locate main")
        return res
    if "main" not in elf.symbols:
        res.notes.append(f"stripped: main located via _start @ {hex(main)}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    names = _name_map(elf)

    # scan main, its direct callees, and all known function symbols
    to_scan = {main}
    part_main, callees = _scan(binary, main, md, names)
    to_scan |= callees
    to_scan |= {a for _, a in binary.functions()}

    parts = {main: part_main}
    for addr in to_scan:
        if addr not in parts:
            parts[addr], _ = _scan(binary, addr, md, names)

    # pick the vulnerable frame: prefer one with an overflow input, else inputs
    def frame_score(p):
        if p.overflow_input():
            return (2, len(p.inputs))
        if p.inputs:
            return (1, len(p.inputs))
        return (0, 0)

    vuln_addr = max(parts, key=lambda a: frame_score(parts[a]))
    vframe = parts[vuln_addr]
    res.inputs = vframe.inputs
    res.checks = vframe.checks
    res.fmt_leaks = vframe.fmt_leaks
    res.canary_off = vframe.canary_off
    if vuln_addr != main:
        res.notes.append(f"vulnerable frame: function @ {hex(vuln_addr)}")

    # flag block / getenv("FLAG") from any scanned frame
    for p in parts.values():
        if p.getenv_flag:
            res.getenv_flag = True
            res.flag_block = res.flag_block or p.flag_block

    return res


def describe(res):
    report.step("Static analysis of main():")
    for i in res.inputs:
        sz = f", {i.size}B" if i.size is not None else ""
        report.info(f"  input: {i.func}  -> rbp{i.off:+#x}{sz}  "
                    f"({'overflow' if i.unbounded else 'bounded'})")
    if not res.inputs:
        report.info("  input: none detected")
    for c in res.checks:
        report.info(f"  strcmp(rbp{c.off:+#x}, {c.const!r})")
    for off in res.fmt_leaks:
        report.info(f"  printf(rbp{off:+#x})  <-- FORMAT STRING (leak primitive)")
    if res.canary_off is not None:
        report.info(f"  canary stored at rbp{res.canary_off:+#x}")
    if res.getenv_flag:
        report.info(f"  getenv(\"FLAG\") printed; flag block @ "
                    f"{hex(res.flag_block) if res.flag_block else '?'}")
    for n, a in res.win_funcs:
        report.info(f"  win function: {n} @ {hex(a)}")
    for note in res.notes:
        report.warn("  " + note)
