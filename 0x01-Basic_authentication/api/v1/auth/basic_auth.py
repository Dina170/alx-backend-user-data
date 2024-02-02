#!/usr/bin/env python3
"""Defines Basic auth class"""
from api.v1.auth.auth import Auth
from base64 import b64decode
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the Authorization header"""
        if not authorization_header or\
                type(authorization_header) is not str or\
                not authorization_header.startswith("Basic "):
            return None
        return authorization_header.split()[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64 string"""
        if type(base64_authorization_header) is not str:
            return None
        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """return the user email and password from the Base64 decoded value"""
        if type(decoded_base64_authorization_header) is not str or\
           ':' not in decoded_base64_authorization_header:
            return (None, None)

        username, password = decoded_base64_authorization_header.split(':', 1)
        return (username, password)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his email and password"""
        if type(user_email) is str and type(user_pwd) is str:
            user = User.search({'email': user_email})
            if user and user[0] and user[0].is_valid_password(user_pwd):
                return user[0]

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieves the User instance for a request"""
        if request:
            auth_token = self.authorization_header(request)
            base64_str = self.extract_base64_authorization_header(auth_token)
            credentials = self.decode_base64_authorization_header(base64_str)
            username, password = self.extract_user_credentials(credentials)
            return self.user_object_from_credentials(username, password)
