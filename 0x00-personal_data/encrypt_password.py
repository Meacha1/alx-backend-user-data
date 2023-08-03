#!/usr/bin/env python3
"""Hash Password Module

This module provides functions for hashing and validating
passwords using bcrypt.

"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Hash the provided password using bcrypt.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password as a byte string.

    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validate a password against a hashed password using bcrypt.

    Args:
        hashed_password (bytes): The hashed password as a byte string.
        password (str): The password to be validated.

    Returns:
        bool: True if the provided password matches the
        hashed password, False otherwise.

    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
