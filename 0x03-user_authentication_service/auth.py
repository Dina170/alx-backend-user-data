#!/usr/bin/env python3
"""Auth Module"""
import bcrypt


def _hash_password(password: str) -> str:
    """returns a salted hash of the input password"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
