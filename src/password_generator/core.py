from __future__ import annotations

from dataclasses import dataclass
import math
import secrets
import string

AMBIGUOUS = set("Il1O0o|`'\"")


@dataclass(frozen=True)
class PasswordPolicy:
    """Rules used when generating a password."""

    length: int = 20
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False

    def character_groups(self) -> list[str]:
        groups: list[str] = []
        if self.lowercase:
            groups.append(string.ascii_lowercase)
        if self.uppercase:
            groups.append(string.ascii_uppercase)
        if self.digits:
            groups.append(string.digits)
        if self.symbols:
            groups.append("!@#$%^&*()-_=+[]{}:,.?")

        if self.exclude_ambiguous:
            groups = ["".join(ch for ch in group if ch not in AMBIGUOUS) for group in groups]

        groups = [group for group in groups if group]
        if not groups:
            raise ValueError("At least one character group must be enabled.")
        if self.length < len(groups):
            raise ValueError(
                "Password length must be at least the number of enabled character groups."
            )
        return groups


def generate_password(policy: PasswordPolicy | None = None) -> str:
    """Generate a password using cryptographically secure randomness.

    At least one character from each enabled group is guaranteed to appear.
    """

    policy = policy or PasswordPolicy()
    groups = policy.character_groups()
    pool = "".join(groups)

    characters = [secrets.choice(group) for group in groups]
    characters.extend(secrets.choice(pool) for _ in range(policy.length - len(groups)))

    # SystemRandom uses the operating system's secure randomness source.
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def estimate_entropy_bits(policy: PasswordPolicy | None = None) -> float:
    """Return a conservative entropy estimate based on pool size and length."""

    policy = policy or PasswordPolicy()
    pool = "".join(policy.character_groups())
    return policy.length * math.log2(len(set(pool)))
