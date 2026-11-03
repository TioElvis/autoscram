"""Strategy base class."""


class Strategy:
    name = "base"
    desc = ""

    def detect(self, ctx):
        """Return (score, reason). score<=0 means 'not applicable'.
        Higher score = more likely to be the intended path."""
        return 0, "n/a"

    def build(self, ctx):
        """Return (payload: bytes|None, interactive: bool, note: str).
        payload None means the strategy could not build one."""
        return None, False, "not built"

    # strategies that spawn a shell can't be verified by a flag-in-output check
    verifiable = True
