#!/usr/bin/env python3
"""QingBruteForce: offline password search-space and strength analyzer.

This program does not perform login attempts, generate attack lists, or crack
passwords. Password analysis is performed locally and the entered password is
never written to disk.
"""

from __future__ import annotations

import argparse
import getpass
import math
import string
import sys

VERSION = "1.0.0"

CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
    "letters": string.ascii_letters,
    "alnum": string.ascii_letters + string.digits,
    "all": string.ascii_letters + string.digits + string.punctuation,
    "printable": string.printable.rstrip(),
}


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds:.3g} seconds"
    units = (
        ("year", 365.25 * 24 * 60 * 60),
        ("day", 24 * 60 * 60),
        ("hour", 60 * 60),
        ("minute", 60),
        ("second", 1),
    )
    remaining = seconds
    parts = []
    for name, size in units:
        amount = int(remaining // size)
        if amount:
            parts.append(f"{amount:,} {name}{'' if amount == 1 else 's'}")
            remaining -= amount * size
        if len(parts) == 2:
            break
    return ", ".join(parts) if parts else "< 1 second"


def estimate(args: argparse.Namespace) -> int:
    if not 1 <= args.length <= 20:
        print("Error: --length must be between 1 and 20.", file=sys.stderr)
        return 2
    if args.charset_size is not None:
        size = args.charset_size
    else:
        size = len(CHARSETS[args.charset])
    if size < 1:
        print("Error: character-set size must be at least 1.", file=sys.stderr)
        return 2
    total = size ** args.length

    print("\nQINGBRUTEFORCE — SEARCH-SPACE ESTIMATE")
    print("=" * 44)
    print(f"Password length       : {args.length}")
    print(f"Character-set size    : {size}")
    print(f"Possible combinations: {total:,}")
    print(f"Digits in search space: {len(str(total))}")
    if args.rate is not None:
        if args.rate <= 0:
            print("Error: --rate must be greater than zero.", file=sys.stderr)
            return 2
        seconds = total / args.rate
        print(f"Assumed rate          : {args.rate:,.2f} checks/second")
        print(f"Time for full search  : {format_duration(seconds)}")
        print(f"Average search time   : {format_duration(seconds / 2)}")
    print("=" * 44)
    print("These are mathematical estimates, not a promise of real-world speed.")
    return 0


def analyze(_: argparse.Namespace) -> int:
    print("Enter a password for local analysis. It will not be saved.")
    try:
        password = getpass.getpass("Password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 130

    if not password:
        print("No password entered.")
        return 2

    groups = [
        ("lowercase", any(c in string.ascii_lowercase for c in password), 26),
        ("uppercase", any(c in string.ascii_uppercase for c in password), 26),
        ("digits", any(c in string.digits for c in password), 10),
        ("symbols", any(c in string.punctuation for c in password), len(string.punctuation)),
        ("other characters", any(not c.isascii() for c in password), 100),
    ]
    pool = sum(size for _, present, size in groups if present)
    entropy = len(password) * math.log2(pool) if pool else 0.0

    print("\nLOCAL PASSWORD REVIEW")
    print("=" * 36)
    print(f"Length: {len(password)} characters")
    print("Character groups:")
    for label, present, _ in groups:
        print(f"  {'[x]' if present else '[ ]'} {label}")

    if len(password) < 12:
        advice = "Too short for a strong general-purpose password."
    elif entropy < 60:
        advice = "Consider a longer, less predictable password."
    elif entropy < 80:
        advice = "Reasonable variety, but a longer unique password is better."
    else:
        advice = "Good estimated search-space characteristics."

    lowered = password.lower()
    common_fragments = ("password", "qwerty", "123456", "letmein", "admin")
    if any(fragment in lowered for fragment in common_fragments):
        advice = "Contains a widely used pattern. Replace it with a unique passphrase."

    print(f"Estimated character-pool entropy: {entropy:.1f} bits")
    print(f"Guidance: {advice}")
    print("=" * 36)
    print("This is a rough estimate, not a breach-database or reuse check.")
    print("Do not reuse passwords. Use a password manager and MFA.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qingbruteforce",
        description="Offline password search-space and strength analyzer.",
        epilog="This tool does not attempt logins or crack account passwords.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    calc = sub.add_parser("estimate", help="calculate a theoretical search space")
    calc.add_argument("--length", type=int, required=True, help="password length (1–20)")
    calc.add_argument(
        "--charset",
        choices=sorted(CHARSETS),
        default="all",
        help="built-in character set (default: all)",
    )
    calc.add_argument(
        "--charset-size",
        type=int,
        help="custom number of possible characters; overrides --charset",
    )
    calc.add_argument(
        "--rate",
        type=float,
        help="hypothetical checks per second for a mathematical time estimate",
    )
    calc.set_defaults(func=estimate)

    review = sub.add_parser("analyze", help="review a password locally without saving it")
    review.set_defaults(func=analyze)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
