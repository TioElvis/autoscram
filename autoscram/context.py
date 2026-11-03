"""Shared context passed to every strategy."""
from . import offset as offset_mod


class Context:
    def __init__(self, binary, analysis, args, flag_re):
        self.binary = binary
        self.analysis = analysis
        self.args = args
        self.flag_re = flag_re
        self._offset = args.offset if getattr(args, "offset", None) is not None else None

    def ret_offset(self):
        """Lazily compute (and cache) the RET offset."""
        if self._offset is None:
            self._offset = offset_mod.find_ret_offset(self.binary.path)
        return self._offset
