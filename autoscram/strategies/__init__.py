"""Exploit strategies. Each is a Strategy subclass; ALL lists them in priority."""
from .data_overflow import DataOverflow
from .ret2win import Ret2Win
from .ret2system import Ret2System

# Order here is only a tie-break; detect() scores drive the real ranking.
ALL = [DataOverflow(), Ret2System(), Ret2Win()]
