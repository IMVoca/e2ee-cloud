import pytest

from common.kdf import KEY_LEN, SALT_LEN, derive_master_key, new_salt


def test_key_length():
    assert len(derive_master_key("pw", new_salt())) == KEY_LEN


def test_deterministic():
    salt = new_salt()
    assert derive_master_key("pw", salt) == derive_master_key("pw", salt)


def test_str_and_bytes_equivalent():
    salt = new_salt()
    assert derive_master_key("密碼", salt) == derive_master_key("密碼".encode(), salt)


def test_different_password_or_salt_gives_different_key():
    salt = new_salt()
    k = derive_master_key("pw", salt)
    assert derive_master_key("pw2", salt) != k
    assert derive_master_key("pw", new_salt()) != k


def test_salt_length_enforced():
    assert len(new_salt()) == SALT_LEN
    with pytest.raises(ValueError):
        derive_master_key("pw", b"short")
