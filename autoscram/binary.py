"""Binary: thin wrapper around pwntools ELF with protection flags and helpers."""
from pwn import ELF

from . import report


class Binary:
    def __init__(self, path):
        self.path = path
        self.elf = ELF(path, checksec=False)

    # --- protections ---
    @property
    def pie(self):    return self.elf.pie
    @property
    def nx(self):     return self.elf.nx
    @property
    def canary(self): return self.elf.canary
    @property
    def arch(self):   return self.elf.arch
    @property
    def relro(self):  return self.elf.relro

    def summary(self):
        report.info(
            f"Arch={self.arch}  PIE={'on' if self.pie else 'off'}  "
            f"NX={'on' if self.nx else 'off'}  "
            f"Canary={'yes' if self.canary else 'no'}  "
            f"RELRO={self.relro or 'none'}")
        if self.canary:
            report.warn("Stack canary present: a plain overflow is caught; "
                        "you likely need a canary leak first.")
        if self.pie:
            report.warn("PIE on: static code addresses need a runtime leak.")

    # --- introspection helpers ---
    def imports(self):
        return set(self.elf.plt.keys()) | {
            n for n in self.elf.symbols
            if n in ("gets", "system", "read", "scanf", "__isoc23_scanf")}

    def has(self, name):
        return name in self.elf.plt or name in self.elf.symbols

    def binsh(self):
        return next(self.elf.search(b"/bin/sh\x00"), None)

    def read_cstr(self, vaddr, maxlen=128):
        try:
            data = self.elf.read(vaddr, maxlen)
            return data.split(b"\x00", 1)[0]
        except Exception:
            return b""

    def in_executable(self, addr):
        try:
            for seg in self.elf.iter_segments():
                if seg.header.p_type != "PT_LOAD":
                    continue
                if not (seg.header.p_flags & 1):          # PF_X
                    continue
                start = seg.header.p_vaddr
                if start <= addr < start + seg.header.p_memsz:
                    return True
        except Exception:
            return False
        return False

    def ret_gadget(self):
        for addr in self.elf.search(b"\xc3"):
            if self.in_executable(addr):
                return addr
        return None

    def functions(self):
        """All executable, named symbols, sorted by address."""
        out = []
        for name, addr in self.elf.symbols.items():
            if self.in_executable(addr) and not name.startswith("_") and "@" not in name:
                out.append((name, addr))
        return sorted(set(out), key=lambda x: x[1])
