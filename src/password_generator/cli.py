from __future__ import annotations

import argparse

from .core import PasswordPolicy, estimate_entropy_bits, generate_password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate cryptographically secure passwords.")
    parser.add_argument("-l", "--length", type=int, default=20, help="Password length")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of passwords")
    parser.add_argument("--no-lowercase", action="store_true")
    parser.add_argument("--no-uppercase", action="store_true")
    parser.add_argument("--no-digits", action="store_true")
    parser.add_argument("--no-symbols", action="store_true")
    parser.add_argument("--exclude-ambiguous", action="store_true")
    parser.add_argument("--show-entropy", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.count < 1:
        raise SystemExit("--count must be at least 1")

    policy = PasswordPolicy(
        length=args.length,
        lowercase=not args.no_lowercase,
        uppercase=not args.no_uppercase,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
        exclude_ambiguous=args.exclude_ambiguous,
    )

    try:
        passwords = [generate_password(policy) for _ in range(args.count)]
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    for password in passwords:
        print(password)

    if args.show_entropy:
        print(f"Estimated search-space entropy: {estimate_entropy_bits(policy):.1f} bits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
