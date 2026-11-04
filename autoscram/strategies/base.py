"""Strategy base class.

Two kinds of strategy:
  * single-shot  -> implement build(ctx); the default run() sends the payload.
  * multi-stage  -> override run(ctx, io) to drive the whole conversation
                    (e.g. leak a canary, then overflow).
"""
from .. import report
from ..comms import run_payload


class Strategy:
    name = "base"
    desc = ""
    verifiable = True          # can be self-tested by looking for the flag
    interactive = False        # spawns a shell instead of printing a flag

    def detect(self, ctx):
        """Return (score, reason). score<=0 => not applicable."""
        return 0, "n/a"

    def build(self, ctx):
        """Single-shot payload: return (payload|None, interactive, note)."""
        return None, False, "not built"

    def run(self, ctx, io):
        """Drive the exploit over `io`. Return the flag string, or None.
        Default implementation sends a single build() payload."""
        payload, interactive, note = self.build(ctx)
        if payload is None:
            report.warn(f"{self.name}: {note}")
            return None
        report.ok(f"{self.name}: {note}")
        return run_payload(io, payload, interactive=interactive,
                           flag_re=ctx.flag_re)
