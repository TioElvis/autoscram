"""Connect to a local or remote target, send a payload, detect the flag."""
import re

from pwn import process, remote

from . import report

DEFAULT_FLAG_RE = r"[A-Za-z0-9_]{0,24}\{[^}\n]{1,120}\}"


def connect(bin_path, remote_target=None, env=None):
    if remote_target:
        host, port = remote_target
        report.step(f"Connecting to {host}:{port} ...")
        return remote(host, port)
    return process(bin_path, env=env)


def run_payload(io, payload, interactive=False, flag_re=DEFAULT_FLAG_RE,
                feed=b""):
    """Send feed (optional) + payload, then collect output or hand over a shell.

    Returns the matched flag string, or None.
    """
    if feed:
        io.send(feed)
    io.sendline(payload)

    if interactive:
        report.ok("Payload sent - dropping to interactive shell "
                  "(try: cat flag*, id, ls).")
        try:
            io.sendline(b"echo SCRAM_$(id -u 2>/dev/null); cat flag* 2>/dev/null")
        except Exception:
            pass
        io.interactive()
        return None

    try:
        data = io.recvall(timeout=5)
    except Exception:
        data = b""
    text = data.decode(errors="replace")
    if text.strip():
        report.info("Target output:")
        print(text)
    m = re.search(flag_re, text)
    if m:
        report.ok(f"FLAG: {m.group(0)}")
        return m.group(0)
    return None


def self_test(bin_path, payload, flag_re=DEFAULT_FLAG_RE,
              sentinel="SCRAMSELFTEST", extra_env=None, feed=b""):
    """Run the LOCAL copy with FLAG=sentinel and check the exploit prints it.

    Lets us verify a payload before firing it at the remote. Returns bool.
    """
    import os
    env = dict(os.environ)
    env["FLAG"] = f"FLAG{{{sentinel}}}"
    if extra_env:
        env.update(extra_env)
    try:
        io = process(bin_path, env=env)
        if feed:
            io.send(feed)
        io.sendline(payload)
        data = io.recvall(timeout=4)
    except Exception:
        return False
    return sentinel.encode() in data
