import pytest
from securecrypto import hash_utils
from argon2.exceptions import VerifyMismatchError


def test_hash_password_and_verify():
    password = "StrongPass123!"
    hashed = hash_utils.hash_password_secure(password)
    assert hashed is not None

    from argon2 import PasswordHasher

    ph = PasswordHasher()
    try:
        ph.verify(hashed, password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified is True


def test_wrong_password_verification():
    password = "CorrectPass"
    wrong_password = "WrongPass"
    hashed = hash_utils.hash_password_secure(password)

    from argon2 import PasswordHasher

    ph = PasswordHasher()
    try:
        ph.verify(hashed, wrong_password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified is False
