"""Static analysis of `main`: find input buffers, strcmp checks, the flag block.

Uses capstone to walk main linearly and track rbp-relative addresses so it can
answer: where does the vulnerable read land, which fixed strings are compared
against which buffer offsets, and where is the block that prints the flag.
"""
from dataclasses import dataclass, field

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

from . import report

WIN_KEYWORDS = ("win", "flag", "shell", "backdoor", "secret", "giveshell",
                "give_shell", "get_shell", "getshell", "print_flag", "get_flag",
                "cat_flag", "readflag", "admin", "magic", "success", "pwn")

UNBOUNDED_READS = ("gets", "__isoc23_scanf", "scanf")


@dataclass
class InputSite:
    func: str            # scanf / gets
    off: int             # rbp-relative offset where input lands
    unbounded: bool


@dataclass
class Check:
    off: int             # rbp-relative offset of the compared buffer
    const: bytes         # the fixed string it's compared against


@dataclass
class Analysis:
    inputs: list = field(default_factory=list)      # list[InputSite]
    checks: list = field(default_factory=list)      # list[Check]
    getenv_flag: bool = False
    flag_block: int = None                          # best-effort ret2win target
    win_funcs: list = field(default_factory=list)   # [(name, addr)]
    notes: list = field(default_factory=list)

    @property
    def primary_input(self):
        return self.inputs[0] if self.inputs else None


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
    """Return main's address, even on stripped binaries.

    On a stripped ELF there's no 'main' symbol, but _start passes main's
    address to __libc_start_main in RDI just before the first call."""
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
            break               # first call = __libc_start_main
    return rdi


def analyze(binary):
    """Return an Analysis for the binary's main()."""
    elf = binary.elf
    res = Analysis()

    # win functions from symbols
    for name, addr in binary.functions():
        low = name.lower()
        if any(k in low for k in WIN_KEYWORDS):
            res.win_funcs.append((name, addr))

    main = find_main(binary)
    if main is None:
        res.notes.append("could not locate main (stripped + unusual _start)")
        return res
    if "main" not in elf.symbols:
        res.notes.append(f"stripped: main located via _start @ {hex(main)}")

    try:
        code = elf.read(main, 0x800)
    except Exception:
        res.notes.append("could not read main's bytes")
        return res

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    names = _name_map(elf)

    # register state: reg -> ('rbp', disp) | ('str', vaddr, text) | None
    regs = {}
    block_start = main          # start of current basic block
    pending_block = False       # next insn starts a new block (after a jcc)

    def val_of(reg):
        return regs.get(reg)

    for insn in md.disasm(code, main):
        if pending_block:
            block_start = insn.address
            pending_block = False

        mn = insn.mnemonic
        ops = insn.operands

        # ---- track address computations ----
        if mn == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_MEM:
            dst = insn.reg_name(ops[0].reg)
            mem = ops[1].mem
            base = insn.reg_name(mem.base) if mem.base else None
            disp = mem.disp
            if base == "rbp":
                regs[dst] = ("rbp", disp)
            elif base == "rip":
                vaddr = insn.address + insn.size + disp
                regs[dst] = ("str", vaddr, binary.read_cstr(vaddr))
            elif base and val_of(base) and val_of(base)[0] == "rbp":
                regs[dst] = ("rbp", val_of(base)[1] + disp)
            else:
                regs[dst] = None

        elif mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG:
            dst = insn.reg_name(ops[0].reg)
            if ops[1].type == X86_OP_REG:
                regs[dst] = val_of(insn.reg_name(ops[1].reg))
            elif ops[1].type == X86_OP_IMM:
                regs[dst] = ("imm", ops[1].imm)
            else:
                regs[dst] = None

        elif mn == "add" and len(ops) == 2 and ops[0].type == X86_OP_REG \
                and ops[1].type == X86_OP_IMM:
            dst = insn.reg_name(ops[0].reg)
            cur = val_of(dst)
            if cur and cur[0] == "rbp":
                regs[dst] = ("rbp", cur[1] + ops[1].imm)

        # ---- basic-block tracking ----
        if mn.startswith("j") and mn != "jmp":
            pending_block = True

        # ---- calls ----
        if mn == "call" and ops and ops[0].type == X86_OP_IMM:
            target = ops[0].imm
            fname = _norm(names.get(target, ""))
            rdi, rsi = val_of("rdi"), val_of("rsi")

            if fname == "scanf":
                fmt = rdi if (rdi and rdi[0] == "str") else None
                buf = rsi if (rsi and rsi[0] == "rbp") else None
                if buf is not None:
                    unb = True
                    if fmt and b"%" in fmt[2]:
                        # unbounded only if %s with no width
                        unb = b"%s" in fmt[2]
                    res.inputs.append(InputSite("scanf", buf[1], unb))
            elif fname in ("gets",):
                buf = rdi if (rdi and rdi[0] == "rbp") else None
                if buf is not None:
                    res.inputs.append(InputSite("gets", buf[1], True))
            elif fname == "strcmp":
                a, b = rdi, rsi
                buf = const = None
                for v in (a, b):
                    if v and v[0] == "rbp":
                        buf = v
                    elif v and v[0] == "str":
                        const = v
                if buf is not None and const is not None:
                    res.checks.append(Check(buf[1], const[2]))
            elif fname == "getenv":
                if rdi and rdi[0] == "str" and rdi[2] == b"FLAG":
                    res.getenv_flag = True
                    res.flag_block = block_start

        if mn == "ret":
            break

    return res


def describe(res):
    report.step("Static analysis of main():")
    if res.primary_input:
        i = res.primary_input
        report.info(f"  input: {i.func}  -> buffer at rbp{i.off:+#x}"
                    f"  ({'unbounded' if i.unbounded else 'bounded'})")
    else:
        report.info("  input: none detected")
    for c in res.checks:
        report.info(f"  strcmp(rbp{c.off:+#x}, {c.const!r})")
    if res.getenv_flag:
        report.info(f"  getenv(\"FLAG\") printed; flag block @ "
                    f"{hex(res.flag_block) if res.flag_block else '?'}")
    for n, a in res.win_funcs:
        report.info(f"  win function: {n} @ {hex(a)}")
    for note in res.notes:
        report.warn("  " + note)
