"""Tiny colored logger so modules don't depend on pwntools' global log state."""
import sys

_COL = {"info": "34", "ok": "32", "warn": "33", "err": "31", "step": "36"}
_TAG = {"info": "*", "ok": "+", "warn": "!", "err": "-", "step": ">"}


def _emit(kind, msg):
    tag, col = _TAG[kind], _COL[kind]
    sys.stderr.write(f"\x1b[{col}m[{tag}]\x1b[0m {msg}\n")
    sys.stderr.flush()


def info(m): _emit("info", m)
def ok(m):   _emit("ok", m)
def warn(m): _emit("warn", m)
def err(m):  _emit("err", m)
def step(m): _emit("step", m)


def banner():
    sys.stderr.write(r"""
  ___  ___ _ __ __ _ _ __ ___
 / __|/ __| '__/ _` | '_ ` _ \
 \__ \ (__| | | (_| | | | | | |
 |___/\___|_|  \__,_|_| |_| |_|
  AUTOSCRAM - modular CTF auto-pwn
""")
    sys.stderr.flush()
