"""Exploit strategies. ALL is the registry the orchestrator ranks."""
from .data_overflow import DataOverflow
from .ret2win import Ret2Win
from .ret2system import Ret2System
from .fmt_leak import FmtLeakRet2Win
from .flag_checker import FlagChecker
from .subcipher import SubstitutionCipher
from .magic_decode import MagicDecode

# Order is only a tie-break; detect() scores drive the real ranking.
ALL = [FmtLeakRet2Win(), DataOverflow(), Ret2System(), Ret2Win(),
       FlagChecker(), SubstitutionCipher(), MagicDecode()]
