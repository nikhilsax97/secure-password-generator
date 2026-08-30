# Secure Password Generator

A Python command-line tool for generating randomized passwords with cryptographically secure randomness. The generator guarantees at least one character from every enabled character class and supports configurable length, character sets, ambiguous-character filtering, and basic entropy estimation.

## Features

- Uses Python's `secrets` module instead of pseudo-random generators intended for simulation
- Configurable lowercase, uppercase, digit, and symbol sets
- Optional ambiguous-character filtering
- Generates multiple passwords in one command
- Estimates password search-space entropy
- Unit tests cover policy validation and generated-password properties
- GitHub Actions workflow runs the test suite automatically

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`.

## Usage

```bash
secure-password
secure-password --length 28 --count 3
secure-password --exclude-ambiguous --show-entropy
secure-password --no-symbols --length 18
```

## Tests

```bash
pytest -q
```

## Security Notes

The project uses `secrets.choice` and `secrets.SystemRandom`, which are designed for security-sensitive randomness. The entropy value is a search-space estimate rather than a guarantee of real-world password strength; password reuse, phishing, credential theft, and weak storage can still compromise strong passwords.
