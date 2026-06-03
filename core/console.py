# Helpers for colored terminal output. Colors are disabled when the output is not
# a real terminal, and stdout is forced to UTF-8 so an odd byte never crashes print().

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"

RISK_COLORS = {
    "SAFE": GREEN,
    "LOW": YELLOW,
    "MEDIUM": YELLOW,
    "HIGH": RED,
    "CRITICAL": RED,
}


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # stdout
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    except Exception:
        return False


def _force_utf8():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


_force_utf8()
USE_COLOR = bool(getattr(sys.stdout, "isatty", lambda: False)()) and _enable_windows_ansi()


def color(text, *codes) -> str:
    if not USE_COLOR or not codes:
        return str(text)
    return "".join(codes) + str(text) + RESET


def risk_color(level: str) -> str:
    return RISK_COLORS.get(level, WHITE)


def rule(char: str = "-", width: int = 65) -> str:
    return char * width
