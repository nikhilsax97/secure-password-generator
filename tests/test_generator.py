import string

import pytest

from password_generator.core import AMBIGUOUS, PasswordPolicy, estimate_entropy_bits, generate_password


def test_default_password_has_expected_length_and_character_classes():
    password = generate_password()
    assert len(password) == 20
    assert any(ch in string.ascii_lowercase for ch in password)
    assert any(ch in string.ascii_uppercase for ch in password)
    assert any(ch in string.digits for ch in password)
    assert any(ch in "!@#$%^&*()-_=+[]{}:,.?" for ch in password)


def test_can_generate_digits_only():
    policy = PasswordPolicy(length=32, lowercase=False, uppercase=False, symbols=False)
    password = generate_password(policy)
    assert len(password) == 32
    assert password.isdigit()


def test_excludes_ambiguous_characters():
    policy = PasswordPolicy(length=200, exclude_ambiguous=True)
    password = generate_password(policy)
    assert not (set(password) & AMBIGUOUS)


def test_rejects_policy_with_no_enabled_groups():
    policy = PasswordPolicy(
        length=20, lowercase=False, uppercase=False, digits=False, symbols=False
    )
    with pytest.raises(ValueError, match="At least one"):
        generate_password(policy)


def test_rejects_length_too_short_for_enabled_groups():
    with pytest.raises(ValueError, match="at least"):
        generate_password(PasswordPolicy(length=3))


def test_entropy_increases_with_length():
    short = estimate_entropy_bits(PasswordPolicy(length=12))
    long = estimate_entropy_bits(PasswordPolicy(length=24))
    assert long > short
