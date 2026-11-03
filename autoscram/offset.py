"""Automatic RET-offset discovery via a cyclic pattern + corefile."""
import resource

from pwn import process, cyclic, cyclic_find, p64

from . import report


def _enable_cores():
    try:
        resource.setrlimit(resource.RLIMIT_CORE,
                           (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    except Exception:
        report.warn("Could not raise RLIMIT_CORE; run `ulimit -c unlimited`.")


def find_ret_offset(bin_path, feed=b"", length=2048):
    """Crash bin_path with a De Bruijn pattern and return the RET offset.

    `feed` is any input that must precede the overflowing read (rare).
    Returns an int offset, or None if it couldn't be determined.
    """
    _enable_cores()
    report.step("Computing RET offset with a cyclic pattern...")
    try:
        io = process(bin_path)
        if feed:
            io.send(feed)
        io.sendline(cyclic(length, n=8))
        io.wait()
        core = io.corefile
    except Exception as e:
        report.err(f"Offset calc failed: {e}")
        return None

    off = cyclic_find(p64(core.fault_addr), n=8)        # bytes ret jumped to
    if off < 0:
        off = cyclic_find(p64(core.rip), n=8)           # ret succeeded -> RIP
    if off < 0:
        try:
            off = cyclic_find(core.read(core.rsp, 8), n=8)   # #GP on ret
        except Exception:
            off = -1
    try:
        core.unlink()
    except Exception:
        pass

    if off < 0:
        report.err("Could not determine the offset automatically.")
        return None
    report.ok(f"RET offset = {off}")
    return off
