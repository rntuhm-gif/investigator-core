"""Colored terminal output."""
import sys

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "cyan": "\033[96m",
    "gray": "\033[90m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def cprint(text, color="", file=sys.stdout):
    if color:
        c = COLORS.get(color, "")
        reset = COLORS["reset"]
        print(f"{c}{text}{reset}", file=file)
    else:
        print(text, file=file)

