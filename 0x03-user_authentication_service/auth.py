#!/usr/bin/env python3
"""Auth Module"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> str:
    """returns a salted hash of the input password"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """initialize"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """register a user"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except NoResultFound:
            user = self._db.add_user(email, _hash_password(password))
            return user
