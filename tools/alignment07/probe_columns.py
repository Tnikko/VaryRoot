"""Derive the coordinate-only UTF-8/CRLF variant of the Step 04 reviewed TU."""
from pathlib import Path
import sys


def variant(raw):
    # Include an astral code point and a tab to distinguish common column units.
    return raw.replace("/* 宽度 */".encode(), "\t/* 宽度🙂 */".encode()).replace(b"\n", b"\r\n")


if __name__ == "__main__":
    path = Path(sys.argv[1])
    path.write_bytes(variant(path.read_bytes()))
